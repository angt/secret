# secret

Keep your little secrets, publicly.

## Features

`secret` is the simplest secret store you can think of:

 - Requires only one file `~/.secret` that you can share publicly without fear.
 - No configuration. Get back your file and you're done.
 - Secret's name (hostname, mail, login, etc.) are also encrypted.
 - Secret agent only trusts subprocesses. Not all user processes! How nice is that?
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

| Command            | Description                                         |
|--------------------|-----------------------------------------------------|
| init               | Init a secret storage for the user at `~/.secret`.  |
| list               | List all secrets for a given passphrase.            |
| add KEY            | Add a new secret.                                   |
| show KEY           | Show an existing secret.                            |
| change KEY         | Change an existing secret.                          |
| agent CMD [ARG]... | Run a process in a trusted zone. Typically a shell. |

You can use a different store using the `SECRET_STORE` environment variable:

    $ env SECRET_STORE=<FILE> secret ...

## Examples

Initialize secret for the current user:

    $ secret init

Add a new randomly generated secret:

    $ secret add test
    Passphrase:
    Secret [random]:
    9{6u0ue>5&W2+z#OR:`X<@-#

Show the secret:

    $ secret show test
    Passphrase:
    9{6u0ue>5&W2+z#OR:`X<@-#

Start `bash` in a trusted zone:

    $ secret agent bash
    Passphrase:

Now, the passphrase is not requested and completion fully works!

---
For feature requests and bug reports,
please create an [issue](https://github.com/angt/secret/issues).
