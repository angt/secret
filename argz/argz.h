#pragma once

struct argz {
    char *name;
    char *help;
    int (*call)(int, char **, void *);
    void *data;
    const char *const *alt;
    unsigned grp;
    int set;
};

int  argz_help  (int, char **);
void argz_print (struct argz *);
int  argz       (int, char **, void *);
