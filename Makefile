CC     = cc
CFLAGS = -Wall -O2
prefix = /usr/local

secret:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) secret.c -o secret

install: secret
	mkdir -p $(DESTDIR)$(prefix)/bin
	mv -f secret $(DESTDIR)$(prefix)/bin

uninstall:
	rm -f $(DESTDIR)$(prefix)/bin/secret

clean:
	rm -f secret

.PHONY: secret install uninstall clean
