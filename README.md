# secret

Keep your little secrets, publicly.

## Features

 - Only one file to backup: `~/.secret`.
 - No configuration: get back your file and you're done.
 - URLs/logins/scopes are encrypted too.
 - Secret agent that allows shell completion (only `bash` for now).
 - Support many passwords (a visual hash might be required).
 - Depends only on the [libhydrogen](https://libhydrogen.org/) library.
 - Small, simple and non obfuscated C code.

## Build and install

    $ make install prefix=/usr

Currently, bash completion is not installed. Download and source the file [argz.sh](argz/argz.sh) then:

    $ complete -F _argz secret

## Commands

    $ secret
    Available commands:
        init      Init secret storage
        list      List all secrets
        add       Add a new secret
        show      Show a secret
        change    Change a secret
        agent     Exec in secret zone

## Examples

Initialize secret:

    $ secret init

Add a new generated secret called 'test':

    $ secret add test
    Password:
    Secret [random]:
    9{6u0ue>5&W2+z#OR:`X<@-#

Show secret 'test':

    $ secret show test
    Password:
    9{6u0ue>5&W2+z#OR:`X<@-#

Start a secret zone:

    $ secret agent bash
    Password:

You can now manipulate your secrets easily and with completion:

    $ ./secret show test
    9{6u0ue>5&W2+z#OR:`X<@-#

