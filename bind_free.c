//===--  bind_free.c - Bind a program to a free CPU -----------------------===//
//
// Mostly taken from American Fuzzy Lop (AFL), written and maintained by
// Michal Zalewski <lcamtuf@google.com>
//
//
// Copyright 2013 Google LLC All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//===----------------------------------------------------------------------===//

#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Terminal colours
#define cBLK "\x1b[0;30m"
#define cRED "\x1b[0;31m"
#define cGRN "\x1b[0;32m"
#define cBRN "\x1b[0;33m"
#define cBLU "\x1b[0;34m"
#define cMGN "\x1b[0;35m"
#define cCYA "\x1b[0;36m"
#define cLGR "\x1b[0;37m"
#define cGRA "\x1b[1;90m"
#define cLRD "\x1b[1;91m"
#define cLGN "\x1b[1;92m"
#define cYEL "\x1b[1;93m"
#define cLBL "\x1b[1;94m"
#define cPIN "\x1b[1;95m"
#define cLCY "\x1b[1;96m"
#define cBRI "\x1b[1;97m"
#define cRST "\x1b[0m"

#define SUCCESS(x...) printf(cGRN "[+] " cRST x)
#define STATUS(x...) printf(cLBL "[-] " cRST x)
#define WARN(x...) fprintf(stderr, cYEL "[!] " cRST x)

#define FATAL(x...)                                                            \
  do {                                                                         \
    fprintf(stderr, cRED "[!] " cRST x);                                       \
    exit(1);                                                                   \
  } while (0);

#define xcalloc(nmemb, size)                                                   \
  ({                                                                           \
    void *buf = calloc(nmemb, size);                                           \
    if (!buf) {                                                                \
      FATAL("calloc failed\n");                                                \
    }                                                                          \
    buf;                                                                       \
  })

#define alloc_printf(x...)                                                     \
  ({                                                                           \
    char *buf;                                                                 \
    int len = snprintf(NULL, 0, x);                                            \
    buf = xcalloc(len + 1, sizeof(char));                                      \
    snprintf(buf, len + 1, x);                                                 \
    buf;                                                                       \
  })

#define MAX_LINE 2048
#define AVG_SMOOTHING 16

/// Get the number of runnable processess, with some simple smoothing
static double get_runnable_processes(void) {
  double res = 0;

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE *proc_stat = fopen("/proc/stat", "r");
  if (!proc_stat) {
    return 0;
  }

  char tmp[MAX_LINE];
  unsigned val = 0;

  while (fgets(tmp, sizeof(tmp), proc_stat)) {
    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) {
      val += atoi(tmp + 14);
    }
  }

  fclose(proc_stat);

  if (!res) {
    res = val;
  } else {
    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);
  }

  return res;
}

static long get_core_count(void) {
  double cur_runnable = 0;
  long cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

  if (cpu_core_count > 0) {
    cur_runnable = get_runnable_processes();
    SUCCESS("You have %ld CPU core%s and %0.0f runnable tasks (utilization: "
            "%0.0f%%)\n",
            cpu_core_count, cpu_core_count > 1 ? "s" : "", cur_runnable,
            cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1 && cur_runnable > cpu_core_count * 1.5) {
      WARN("System under apparent load, performance may be spotty\n");
    }
  } else {
    cpu_core_count = 0;
    WARN("Unable to determine the number of CPU cores\n");
  }

  return cpu_core_count;
}

static void bind_to_free_cpu(int cpu_core_count, const char *progname) {
  unsigned i = 0;
  struct dirent *proc_entry;
  cpu_set_t c;

  uint8_t cpu_used[4096] = {0};

  if (cpu_core_count < 2) {
    return;
  }

  DIR *proc_dir = opendir("/proc");
  if (!proc_dir) {
    WARN("Unable to access /proc - can't scan for free CPU cores\n");
    return;
  }

  STATUS("Checking CPU core load...\n");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  usleep(random() % 1000 * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((proc_entry = readdir(proc_dir))) {
    FILE *proc_status;
    char tmp[MAX_LINE];
    uint8_t has_vmsize = 0;

    if (!isdigit(proc_entry->d_name[0])) {
      continue;
    }

    char *proc_status_path =
        alloc_printf("/proc/%s/status", proc_entry->d_name);

    if (!(proc_status = fopen(proc_status_path, "r"))) {
      free(proc_status_path);
      continue;
    }

    while (fgets(tmp, MAX_LINE, proc_status)) {
      uint32_t hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) {
        has_vmsize = 1;
      }

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) && !strchr(tmp, '-') &&
          !strchr(tmp, ',') && sscanf(tmp + 19, "%u", &hval) == 1 &&
          hval < sizeof(cpu_used) && has_vmsize) {
        cpu_used[hval] = 1;
        break;
      }
    }

    free(proc_status_path);
    fclose(proc_status);
  }

  closedir(proc_dir);

  for (i = 0; i < cpu_core_count; i++) {
    if (!cpu_used[i]) {
      break;
    }
  }

  if (i == cpu_core_count) {
    FATAL("No more free CPU cores\n");
  }

  SUCCESS("Found a free CPU core, binding `%s` to #%u\n", progname, i);

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c)) {
    FATAL("sched_setaffinity failed\n");
  }
}

int main(int argc, char **argv) {
  int ret = 0;

  if (argc > 1) {
    long cpu_core_count = get_core_count();
    bind_to_free_cpu(cpu_core_count, argv[1]);

    printf("\n");
    ret = execvp(argv[1], &argv[1]);
    FATAL("Failed to execute `%s`: %s\n", argv[1], strerror(errno));
  }

  return ret;
}
