CC     = cc
CFLAGS = -Wall -O2
prefix = /usr/local
PREFIX = $(prefix)

secret:
	$(X)$(CC) $(EXTRA) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) secret.c -o secret

install: secret
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mv -f secret $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/secret

clean:
	rm -f secret

.PHONY: secret install uninstall clean
