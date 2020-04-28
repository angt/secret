#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "argz.h"

int
argz_help(int argc, char **argv)
{
    return argc >= 2 && !strcmp(argv[1], "help");
}

int
argz_help_asked(int argc, char **argv)
{
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "help"))
            return 1;
    }
    return 0;
}

static int
argz_cmp(struct argz *z, char *name)
{
    if (!strcmp(z->name, name))
        return 0;
    if (z->alt) for (unsigned k = 0; z->alt[k]; k++) {
        if (!strcmp(z->alt[k], name))
            return 0;
    }
    return 1;
}

static int
argz_is_available(struct argz *z, unsigned i, unsigned *ret)
{
    if (z[i].set)
        return 0;
    if (z[i].grp) for (unsigned k = 0; z[k].name; k++) {
        if (z[k].set && z[k].grp == z[i].grp) {
            if (ret) *ret = k;
            return 0;
        }
    }
    return 1;
}

void
argz_print(struct argz *z)
{
    int len = 0;

    for (int i = 0; z[i].name; i++) {
        if (!argz_is_available(z, i, NULL))
            continue;
        int nlen = strlen(z[i].name);
        if (len < nlen)
            len = nlen;
    }

    for (int i = 0; z[i].name; i++) {
        if (!argz_is_available(z, i, NULL))
            continue;
        printf("    %-*s    %s\n", len, z[i].name, z[i].help ? z[i].help : "");
    }
}

int
argz(int argc, char **argv, void *data)
{
    struct argz *z = (struct argz *)data;

    if (argz_help(argc, argv)) {
        argz_print(z);
        return 0;
    }

    if (argc > 1) {
        for (unsigned i = 0; z[i].name; i++) {
            if (argz_cmp(&z[i], argv[1]))
                continue;
            unsigned k = 0;
            if (!argz_is_available(z, i, &k)) {
                fprintf(stderr, "cannot call %s because of %s\n", z[i].name, z[k].name);
                return 0;
            }
            int ret = argc - 1;
            if (z[i].call)
                ret = z[i].call(ret, argv + argc - ret, z[i].data);
            return argz(ret, argv + argc - ret, data);
        }
        fprintf(stderr, "Unknown: %s\n", argv[1]);
    }

    return argc;
}
