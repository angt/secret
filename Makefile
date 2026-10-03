CC     = cc
CFLAGS = -Wall -O2
prefix = /usr/local
PREFIX = $(prefix)

secret:
	$(X)$(CC) $(EXTRA) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) secret.c -o $@

wasm:
	zig cc -target wasm32-wasi -Os secret.c -o secret.wasm

install: secret
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mv -f secret $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/secret

clean:
	rm -f secret

.PHONY: secret wasm install uninstall clean
