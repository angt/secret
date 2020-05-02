# secret

Keep your little secrets.

## Compatibility

`secret` should work on a wide variety of architectures and POSIX systems.
It was successfully tested on Linux, OpenBSD, FreeBSD and MacOS.

## Features

`secret` is the simplest secret store you can think of:

 - Requires only one file `~/.secret` that you can share publicly without fear.
 - No configuration. Get back your file and you're done.
 - Secret names (usually hostname, mail, login, etc.) are also encrypted.
 - A secret agent that only trusts subprocesses. Not all the processes of the same user!
 - Secret names completion (on bash only) once the agent is activated.
 - Supports unstored secrets. Derived from some simple keys and a passphrase.
 - Supports multiple passphrases. Not super user-friendly but nice to have.
 - Depends only on the [libhydrogen](https://libhydrogen.org/) library.
 - Small, simple and non obfuscated C code. Well, I hope so :)

## Build and install

Clone the repository recursively:

    $ git clone https://github.com/angt/secret --recursive
    $ cd secret

Then, run as `root`:

    # make install

As usual, you can customize the destination with `DESTDIR` and `prefix`.

Currently, bash completion is not installed.
Download the file [argz.sh](argz/argz.sh) then:

    $ . argz.sh
    $ complete -F _argz secret

Completion for secrets is only available in a trusted shell. See below.

## Commands

Available commands:

        init       Initialize secret for the current user
        list       List all secrets for a given passphrase
        show       Print a secret
        new        Generate a new secret
        set        Set a new secret
        renew      Regenerate an existing secret
        reset      Update an existing secret
        pass       Derivate a new secret
        agent      Run a process in a trusted zone
        version    Show version

All secrets are encrypted in the file `~/.secret`.
You can use a different file with the `SECRET_STORE` environment variable:

    $ env SECRET_STORE=<FILE> secret ...

## Examples

Initialize secret for the current user:

    $ secret init

Add a new randomly generated secret:

    $ secret new test
    Passphrase:
    ^>f.8%]_zoN^jSi0CO_{(yYY5

Show the secret:

    $ secret show test
    Passphrase:
    ^>f.8%]_zoN^jSi0CO_{(yYY5

Derive a deterministic (a.k.a. unstored) secret:

    $ secret pass me@domain.com
    Passphrase:
    a`4$B2mJ=|"HD?b4:/y"?wOaQ

Subkeys are also supported, this allows to update your secret in a clean way:

    $ secret pass me@domain.com 2020
    Passphrase:
    F"1j;-X]t.Pi>.xf5hG,]dUMz

Storing binary secrets is supported:

    $ dd if=/dev/urandom bs=1 count=32 bs=1 2>/dev/null | secret set mykey
    Passphrase:

Then, use a pipe to get it:

    $ secret show mykey | xxd
    Passphrase:
    00000000: 0ee9 cdb3 de0a 3e71 b623 726d 5d7e eb23  ......>q.#rm]~.#
    00000010: 5b43 a458 3fb7 3b96 ea9b 6e47 d302 cae7  [C.X?.;...nG....

Start a trusted zone:

    $ secret agent
    Passphrase:

Now, the passphrase is not requested and completion fully works!

If you don't use `bash` but still want completion,
run `secret agent bash` or (much better) send a PR to add support for your shiny shell :)

---
For feature requests and bug reports,
please create an [issue](https://github.com/angt/secret/issues).
