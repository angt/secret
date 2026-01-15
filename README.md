# secret

A simple and tiny tool that will help you keep your little secrets.

## Features

`secret` is the simplest secret store you can think of.
But it does have some interesting features:

 - Requires only one file `~/.secret` that you can share publicly without fear.
 - No configuration. No directory. Get back your file and you're done.
 - Secret names (usually hostname, mail, login, etc.) are also encrypted.
 - A secret agent that only trusts subprocesses. Not all the processes of the same user!
 - Secret names completion is available after calling the secret agent.
 - Supports unstored secrets. Derived from some simple keys and a passphrase.
 - Supports multiple passphrases. A confirmation is requested for each new passphrase.
 - Supports TOTP natively. The name must contain the word `totp`.
 - Depends only on the [libhydrogen](https://libhydrogen.org/) library.
 - Small, simple and non obfuscated C code. Well, I hope so :)

## Security

The main goal is to have `secret` working on all architectures and to make it very simple to audit.

Luckily, permutation-based cryptography has arrived and makes it possible to achieve this goal with very little code.
In 2020, using a bloated library full of CVEs will not have been reasonable considering the major advances in this field.

Only one cryptographic building block is used, the [Gimli](https://gimli.cr.yp.to/gimli-20170627.pdf) permutation.
All cryptographic operations are derived from this permutation and implemented in the [libhydrogen](https://libhydrogen.org/) library.

## Install

### Download precompiled binaries

You can find the latest gzipped binaries for Linux and macOS [here](https://github.com/angt/secret/releases/latest).

For example, on macos with an intel cpu, do the following:

    $ curl -sSOf https://github.com/angt/secret/releases/latest/download/secret-x86_64-macos.gz
    $ gunzip secret-x86_64-macos.gz
    $ chmod +x secret-x86_64-macos
    $ ./secret-x86_64-macos

### Build from source

This should work on a wide variety of architectures and POSIX systems.
It was successfully tested on Linux, OpenBSD, FreeBSD and MacOS.

Clone the repository recursively:

    $ git clone https://github.com/angt/secret --recursive
    $ cd secret

Then, run as `root`:

    # make install

As usual, you can customize the destination with `DESTDIR` and `prefix`.
Typically if you want to change the default `/usr/local` prefix:

    # make prefix=/usr install

### Tab completion

Tab completion works with `bash`, `zsh` and `yash`.
Unfortunately, it doesn't work out of the box, you have to setup it manually.
Luckily, it's super easy!

Download the file corresponding to your shell:

 - [argz.bash](https://raw.githubusercontent.com/angt/argz/master/comp/argz.bash)
 - [argz.yash](https://raw.githubusercontent.com/angt/argz/master/comp/argz.yash)
 - [argz.zsh](https://raw.githubusercontent.com/angt/argz/master/comp/argz.zsh)

Then, for `bash`, you can add these lines in your `.bashrc`:

    . YOUR_PATH_TO/argz.bash

    complete -F _argz secret

For `yash`, in your `.yashrc`:

    . YOUR_PATH_TO/argz.yash

    function completion/secret {
        command -f completion//reexecute argz
    }

And finally, for `zsh`, in your `.zshrc`:

    . YOUR_PATH_TO/argz.zsh

    compdef _argz secret

Completion for secrets is only available in a trusted shell. See below.

## Commands

Available commands:

    init            Initialize secret
    list            List all secrets for a given passphrase
    show            Print a secret
    dump            Dump a raw secret
    new             Generate a new random secret
    set             Set a new secret
    renew           Regenerate an existing secret
    update          Update an existing secret
    pass            Print a deterministic secret
    agent           Run a process in a trusted zone
    version         Show version

All secrets are encrypted in the file `~/.secret`.
You can use a different file with the `SECRET_STORE` environment variable:

    $ env SECRET_STORE=<FILE> secret ...

## Examples

Initialize secret for the current user:

    $ secret init

Add a new randomly generated secret:

    $ secret new test
    Passphrase:
    No secrets stored with this passphrase.
    Please, retype it to confirm:
    /xK;{%@d~hPh.L'5-Sn{sBQd5

Show the secret:

    $ secret show test
    Passphrase:
    /xK;{%@d~hPh.L'5-Sn{sBQd5

Rename a secret, press ENTER to not change it:

    $ secret update test test2
    Passphrase:
    Secret:

    $ secret show test2
    Passphrase:
    /xK;{%@d~hPh.L'5-Sn{sBQd5

Mark a secret for deletion by renaming, the slot will be reused by the next creation:

    $ secret update test DELETED_test
    Passphrase:
    Secret:

Pipe a secret:

    $ secret show test2 | tr -cd [a-z] | secret update test2
    Passphrase:
    Passphrase:

    $ secret show test2
    Passphrase:
    xdhhnsd

Add a TOTP token:

    $ echo -n JBSWY3DPEHPK3PXP | base32 -d | secret set test/totp
    Passphrase:

    $ secret show test/totp
    Passphrase:
    $ 123456

Add a base32 encoded TOTP token:

    $ echo JBSWY3DPEHPK3PXP | secret set test/totp32
    Passphrase:

    $ secret show test/totp32
    Passphrase:
    $ 123456

Derive a deterministic (a.k.a. unstored) secret:

    $ secret pass me@domain.com
    Passphrase:
    a`4$B2mJ=|"HD?b4:/y"?wOaQ

Subkeys are also supported, this allows to update your secret in a clean way:

    $ secret pass me@domain.com 2020
    Passphrase:
    F"1j;-X]t.Pi>.xf5hG,]dUMz

Add a binary secret:

    $ dd if=/dev/urandom bs=1 count=32 2>/dev/null | secret set mykey
    Passphrase:

    $ secret show mykey | xxd
    Passphrase:
    00000000: 0ee9 cdb3 de0a 3e71 b623 726d 5d7e eb23  ......>q.#rm]~.#
    00000010: 5b43 a458 3fb7 3b96 ea9b 6e47 d302 cae7  [C.X?.;...nG....

Add a multiline secret:

    $ secret set test/multiline << EOF
    first secret line
    second secret line
    EOF

    $ secret show test/multiline
    first secret line
    second secret line

Add a reasonable file as secret: 

    $ cat /tmp/secret_file | secret set test/secret

Start a trusted zone:

    $ secret agent
    Passphrase:

Now, the passphrase is not requested and completion fully works!

If you don't use `bash` but still want completion,
run `secret agent <yourawesomeshell>` or (much better) send a PR to add support for your shiny shell :)

---
For feature requests and bug reports,
please create an [issue](https://github.com/angt/secret/issues).
