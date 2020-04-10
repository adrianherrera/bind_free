bind_free: bind_free.c
	$(CC) -Werror -Wall -O3 -o $@ $(CFLAGS) $^

.PHONY: clean install
clean:
	rm -f bind_free

install: bind_free
	install $< /usr/bin/
