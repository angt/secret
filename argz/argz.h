#pragma once

struct argz {
    char *name;
    char *help;
    int (*f)(int, char **, void *);
    void *data;
    const char *const *alt;
    unsigned grp;
    int set;
};

int  argz       (int, char **, void *);
void argz_print (struct argz *);
