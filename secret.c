#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "argz/argz.c"
#include "libhydrogen/hydrogen.c"

#define S_COUNT(x)  (sizeof(x) / sizeof((x)[0]))
#define S_VER_MAJOR  0U
#define S_VER_MINOR  5U
#define S_ENTRYSIZE  512U
#define S_PWDGENLEN  25U
#define S_KEYLENMAX  255U
#define S_ENV_AGENT "SECRET_AGENT"
#define S_ENV_STORE "SECRET_STORE"

static struct {
    char path[1024];
    int pipe[2];
    union {
        struct {
            uint8_t version;
            uint8_t master[hydro_pwhash_MASTERKEYBYTES];
            uint8_t opslimit[8];
        };
        uint8_t buf[S_ENTRYSIZE];
    } hdr;
    struct {
        uint8_t key[hydro_secretbox_KEYBYTES];
        struct {
            uint8_t slen[2];
            char msg[S_ENTRYSIZE - hydro_secretbox_HEADERBYTES - 2U];
        } entry;
    } x;
    uint8_t enc[S_ENTRYSIZE];
    char ctx_master[hydro_pwhash_CONTEXTBYTES];
    char ctx_secret[hydro_secretbox_CONTEXTBYTES];
    char ctx_passwd[hydro_pwhash_CONTEXTBYTES];
    int known_key;
} s = {
    .pipe = {-1, -1},
    .ctx_master = "MASTER",
    .ctx_secret = "SECRET",
    .ctx_passwd = "PASSWD",
};

_Noreturn static void
s_exit(int code)
{
    hydro_memzero(&s.x, sizeof(s.x));
    exit(code);
}

_Noreturn static void
s_fatal(const char *fmt, ...)
{
    va_list ap;
    char buf[256];
    size_t size = sizeof(buf);

    va_start(ap, fmt);
    int ret = vsnprintf(buf, size, fmt, ap);
    va_end(ap);

    if (ret <= 0) {
        buf[0] = '?';
        size = 1;
    }
    if (size > (size_t)ret)
        size = (size_t)ret;

    char hdr[] = "Fatal: ";
    struct iovec iov[] = {
        {hdr, sizeof(hdr) - 1},
        {buf, size}, {"\n", 1},
    };

    writev(2, iov, 3);
    s_exit(1);
}

_Noreturn static void
s_oops(const int line)
{
    s_fatal("Oops at line %i", line);
    s_exit(2);
}

static size_t
s_read(int fd, void *data, size_t size)
{
    size_t done = 0;
    struct pollfd pfd = {.fd = fd, .events = POLLIN};

    while (done < size) {
        ssize_t r = read(fd, (char *)data + done, size - done);
        if (r == 0)
            break;
        if (r == (ssize_t)-1) switch (errno) {
            case EAGAIN: if (!poll(&pfd, 1, 200)) return 1; /* FALLTHRU */
            case EINTR:  continue;
            default:     s_fatal("read: %s", strerror(errno));
        }
        done += r;
    }
    return done;
}

static size_t
s_write(int fd, const void *data, size_t size)
{
    size_t done = 0;
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};

    while (done < size) {
        ssize_t r = write(fd, (const char *)data + done, size - done);
        if (r == 0)
            break;
        if (r == (ssize_t)-1) switch (errno) {
            case EAGAIN: if (!poll(&pfd, 1, 200)) return 1; /* FALLTHRU */
            case EINTR:  continue;
            default:     s_fatal("write: %s", strerror(errno));
        }
        done += r;
    }
    return done;
}

static size_t
s_input(unsigned char *buf, size_t size, const char *prompt)
{
    const char *tty = "/dev/tty";
    int fd = open(tty, O_RDWR | O_NOCTTY);

    if (fd == -1)
        s_fatal("%s: %s", tty, strerror(errno));

    if (prompt)
        s_write(fd, prompt, strlen(prompt));

    struct termios old;
    tcgetattr(fd, &old);

    struct termios new = old;
    new.c_lflag &= ~(ECHO | ECHONL);
    new.c_lflag |= ICANON;
    new.c_iflag &= ~(INLCR | IGNCR);
    new.c_iflag |= ICRNL;

    tcsetattr(fd, TCSAFLUSH, &new);
    ssize_t ret = read(fd, buf, size);
    tcsetattr(fd, TCSAFLUSH, &old);

    s_write(fd, "\n", 1);
    close(fd);

    if (ret <= 0)
        s_exit(0);

    size_t len = ret - 1;

    if (buf[len] != '\n') {
        if ((size_t)ret == size)
            s_fatal("Input too long!");
        s_exit(0);
    }
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < ' ')
            s_fatal("Invalid input!");
    }
    hydro_memzero(buf + len, size - len);
    return len;
}

static void
s_ask_pass(void *buf, size_t size, const char *prompt)
{
    unsigned char pass[128];
    size_t len = s_input(pass, sizeof(pass), prompt);

    if (!len)
        s_exit(0);

    int r = hydro_pwhash_deterministic(buf, size,
                                       (char *)pass, len,
                                       s.ctx_master, s.hdr.master,
                                       load64_le(s.hdr.opslimit), 0, 1);
    hydro_memzero(pass, sizeof(pass));
    if (r) s_oops(__LINE__);
}

static int
s_open_secret(int use_tty)
{
    int fd = open(s.path, O_RDWR);

    if (fd == -1) switch (errno) {
        case ENOENT: s_fatal("Secret store %s doesn't exist", s.path);
        default:     s_fatal("%s: %s", s.path, strerror(errno));
    }

    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
    };

    if (fcntl(fd, F_SETLKW, &fl))
        s_fatal("Unable to lock %s", s.path);

    if (s_read(fd, s.hdr.buf, sizeof(s.hdr.buf)) != sizeof(s.hdr.buf))
        s_fatal("Unable to read %s", s.path);

    if (s.hdr.version != S_VER_MAJOR)
        s_fatal("Unkown version %" PRIu8, s.hdr.version);

    const char *agent = getenv(S_ENV_AGENT);
    int wfd = -1, rfd = -1;

    if (agent && sscanf(agent, "%d.%d", &wfd, &rfd) == 2 &&
        wfd >= 0 && rfd >= 0 &&
        s_write(wfd, "", 1) == 1 &&
        s_read(rfd, s.x.key, sizeof(s.x.key)) == sizeof(s.x.key))
        return fd;

    if (!use_tty)
        s_exit(0);

    s_ask_pass(s.x.key, sizeof(s.x.key), "Passphrase: ");
    return fd;
}

static size_t
s_keylen(const char *str)
{
    if (!str || !str[0])
        s_fatal("Empty keys are not allowed");

    for (size_t i = 0; i <= S_KEYLENMAX; i++) {
        if (!str[i])
            return i;
        if (str[i] > 0 && str[i] <= ' ')
            s_fatal("Special characaters are not allowed in keys");
    }
    s_fatal("Keys are limited to %u bytes", S_KEYLENMAX);
}

static void
s_print_keys(int use_tty)
{
    int fd = s_open_secret(use_tty);

    while (s_read(fd, s.enc, sizeof(s.enc)) == sizeof(s.enc)) {
        if (hydro_secretbox_decrypt(&s.x.entry,
                                    s.enc, sizeof(s.enc), 0,
                                    s.ctx_secret, s.x.key))
            continue;
        s_write(1, s.x.entry.msg, s_keylen(s.x.entry.msg));
        s_write(1, "\n", 1);
    }
    close(fd);
}

static const char *
s_get_secret(int fd, const char *key, int create)
{
    size_t len = s_keylen(key);

    while (s_read(fd, s.enc, sizeof(s.enc)) == sizeof(s.enc)) {
        if (hydro_secretbox_decrypt(&s.x.entry,
                                    s.enc, sizeof(s.enc), 0,
                                    s.ctx_secret, s.x.key))
            continue;
        if (hydro_equal(s.x.entry.msg, key, len + 1)) {
            if (create)
                s_fatal("Secret %s exists!", key);
            if (lseek(fd, -(off_t)sizeof(s.enc), SEEK_CUR) == (off_t)-1)
                s_fatal("seek: %s", strerror(errno));
            return &s.x.entry.msg[len + 1];
        }
        s.known_key = 1;
    }
    if (!create)
        s_fatal("Secret %s not found", key);

    return NULL;
}

static void
s_set_secret(int fd, const char *key, const unsigned char *secret, size_t slen)
{
    size_t len = s_keylen(key);

    if (len + slen + 1 > sizeof(s.x.entry.msg))
        s_fatal("Entry too big!");

    store16_le(s.x.entry.slen, slen);

    size_t t = 0;
    memcpy(s.x.entry.msg, key, len);           t += len;
    s.x.entry.msg[t] = 0;                      t += 1;
    memcpy(s.x.entry.msg + t, secret, slen);   t += slen;
    hydro_random_buf(s.x.entry.msg + t, sizeof(s.x.entry.msg) - t);

    hydro_secretbox_encrypt(s.enc,
                            &s.x.entry, sizeof(s.x.entry), 0,
                            s.ctx_secret, s.x.key);

    s_write(fd, s.enc, sizeof(s.enc));
}

static int
s_init(int argc, char **argv, void *data)
{
    if (argz_help(argc, argv) || argc != 1) {
        if (isatty(1))
            printf("Usage: %s\n", argv[0]);
        return 0;
    }

    int fd = open(s.path, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (fd == -1) switch (errno) {
        case EEXIST: s_fatal("Secret store %s already exists", s.path);
        default:     s_fatal("%s: %s", s.path, strerror(errno));
    }

    s.hdr.version = 0;
    hydro_random_buf(s.hdr.master, sizeof(s.hdr.master));
    store64_le(s.hdr.opslimit, 10000);
    s_write(fd, s.hdr.buf, sizeof(s.hdr.buf));
    return 0;
}

static int
s_list(int argc, char **argv, void *data)
{
    if (argz_help(argc, argv) || argc != 1) {
        if (isatty(1))
            printf("Usage: %s\n", argv[0]);
        return 0;
    }
    s_print_keys(1);
    return 0;
}

static void
s_normalize_and_show(unsigned char *buf, size_t size)
{
    for (size_t i = 0; i < size; i++)
        buf[i] = '!' + buf[i] % (1U + '~' - '!');

    s_write(1, buf, size);
    if (isatty(1)) s_write(1, "\n", 1);
}

enum s_op {
    s_op_generate = 1,
    s_op_create   = 2,
};

static int
s_do(int argc, char **argv, void *data)
{
    enum s_op op;
    memcpy(&op, data, sizeof(enum s_op));

    if (argz_help(argc, argv) || (argc != 2 && (op || argc != 3))) {
        if (isatty(1)) {
            printf("Usage: %s KEY %s\n", argv[0], op ? "" : "NEWKEY");
        } else if (argc == 2 && !(op & s_op_create)) {
            s_print_keys(0);
        }
        return 0;
    }

    int fd = s_open_secret(1);
    const char *old = s_get_secret(fd, argv[1], op & s_op_create);

    if (!old && !s.known_key) {
        char check[sizeof(s.x.key)];
        s_ask_pass(check, sizeof(check), "Never used? Retype to confirm: ");
        if (!hydro_equal(s.x.key, check, sizeof(check)))
            s_fatal("Passphrases don't match!");
    }

    unsigned char secret[S_ENTRYSIZE];
    size_t len = S_PWDGENLEN;

    if (op & s_op_generate) {
        hydro_memzero(secret, sizeof(secret));
        hydro_random_buf(secret, len);
        s_normalize_and_show(secret, len);
    } else {
        len = isatty(0) ? s_input(secret, sizeof(secret), "Secret: ")
                        : s_read(0, secret, sizeof(secret));
        if (!len && old && argc == 3) {
            len = load16_le(s.x.entry.slen);
            memcpy(secret, old, len);
        }
    }
    if (!len)
        s_exit(0);

    s_set_secret(fd, argv[argc - 1], secret, len);
    close(fd);
    return 0;
}

static int
s_show(int argc, char **argv, void *data)
{
    if (argz_help(argc, argv) || argc != 2) {
        if (isatty(1)) {
            printf("Usage: %s KEY\n", argv[0]);
        } else if (argc == 2) {
            s_print_keys(0);
        }
        return 0;
    }

    int fd = s_open_secret(1);
    const char *secret = s_get_secret(fd, argv[1], 0);

    if (secret) {
        s_write(1, secret, load16_le(s.x.entry.slen));
        if (isatty(1)) s_write(1, "\n", 1);
    }
    close(fd);
    return 0;
}

static int
s_pass(int argc, char **argv, void *data)
{
    if (argz_help(argc, argv) || argc < 2) {
        if (isatty(1))
            printf("Usage: %s KEY [SUBKEY...]\n", argv[0]);
        return 0;
    }
    close(s_open_secret(1));

    uint8_t buf[hydro_pwhash_MASTERKEYBYTES];
    uint8_t key[hydro_pwhash_MASTERKEYBYTES];

    memcpy(key, s.x.key, sizeof(key));

    for (int i = 1; i < argc; i++) {
        int r = hydro_pwhash_deterministic(buf, sizeof(buf),
                                           argv[i], s_keylen(argv[i]),
                                           s.ctx_passwd, key,
                                           load64_le(s.hdr.opslimit), 0, 1);
        memcpy(key, buf, sizeof(key));
        if (r) s_oops(__LINE__);
    }
    s_normalize_and_show(buf, S_PWDGENLEN);
    return 0;
}

static void
s_cloexec(int fd)
{
    if (fcntl(fd, F_SETFD, FD_CLOEXEC))
        s_fatal("cloexec: %s", strerror(errno));
}

static void
s_nonblck(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1)
        return;

    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int
s_agent(int argc, char **argv, void *data)
{
    if (argz_help(argc, argv)) {
        if (isatty(1)) {
            printf("Usage: %s CMD [ARG...]\n", argv[0]);
        } else if (argc == 2) {
            printf("CMD\n");
        }
        return 0;
    }
    if (getenv(S_ENV_AGENT))
        s_fatal("Already running...");

    close(s_open_secret(1));

    int rfd[2], wfd[2];

    if (pipe(rfd) || pipe(wfd) || pipe(s.pipe))
        s_fatal("pipe: %s", strerror(errno));

    s_cloexec(s.pipe[0]); s_cloexec(s.pipe[1]);
    s_nonblck(s.pipe[0]); s_nonblck(s.pipe[1]);

    s_nonblck(rfd[0]); s_nonblck(rfd[1]);
    s_nonblck(wfd[0]); s_nonblck(wfd[1]);

    pid_t pid = fork();

    if (pid == (pid_t)-1)
        s_fatal("fork: %s", strerror(errno));

    if (!pid) {
        close(rfd[0]); close(wfd[1]);
        hydro_memzero(&s.x, sizeof(s.x));

        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%d.%d", rfd[1], wfd[0]);
        setenv(S_ENV_AGENT, tmp, 1);

        if (argv[1]) {
            execvp(argv[1], argv + 1);
        } else {
            char *sh = getenv("SHELL");
            if (!sh) sh = "/bin/sh";
            execl(sh, sh, (char *)NULL);
        }
        s_fatal("%s: %s", argv[1], strerror(errno));
    }

    close(rfd[1]); close(wfd[0]);

    struct pollfd fds[] = {
        {.fd = s.pipe[0], .events = POLLIN},
        {.fd = rfd[0],    .events = POLLIN},
    };

    while (1) {
        if (poll(fds, 1 + (fds[1].fd >= 0), -1) == -1) {
            if (errno == EINTR)
                continue;
            s_fatal("poll: %s", strerror(errno));
        }

        if (fds[0].revents & POLLIN) {
            char tmp;
            read(fds[0].fd, &tmp, 1);

            int status;
            pid_t ret = waitpid(-1, &status, WNOHANG);

            if (ret == (pid_t)-1) switch (errno) {
                case EINTR:  continue;
                case EAGAIN: continue;
                case ECHILD: s_exit(0);
                default:     s_fatal("waitpid: %s", strerror(errno));
            }
            if ((ret == pid) &&
                (WIFEXITED(status) || WIFSIGNALED(status)))
                s_exit(0);
        }

        if (fds[1].revents & (POLLERR | POLLHUP)) {
            close(rfd[0]); close(wfd[1]);
            fds[1].fd = -1;
        } else if (fds[1].revents & POLLIN) {
            char tmp;
            read(fds[1].fd, &tmp, 1);
            fds[1].fd = wfd[1];
            fds[1].events = POLLOUT;
        } else if (fds[1].revents & POLLOUT) {
            write(fds[1].fd, s.x.key, sizeof(s.x.key));
            fds[1].fd = rfd[0];
            fds[1].events = POLLIN;
        }
    }
}

static void
s_handler(int sig)
{
    int err = errno;

    if (sig == SIGCHLD && s.pipe[1] != -1)
        write(s.pipe[1], "", 1);

    errno = err;
}

static void
s_set_signals(void)
{
    int sig[] = {
        SIGHUP,  SIGINT,  SIGQUIT,
        SIGUSR1, SIGUSR2, SIGPIPE,
        SIGALRM, SIGTERM, SIGTSTP,
        SIGTTIN, SIGCHLD,
    };

    struct sigaction sa = {
        .sa_handler = s_handler,
    };

    for (size_t i = 0; i < S_COUNT(sig); i++)
        sigaction(sig[i], &sa, NULL);
}

static void
s_set_path(void)
{
    struct {
        const char *fmt, *env;
    } path[] = {
        {"%s",    getenv(S_ENV_STORE)},
        {"%s/.secret", getenv("HOME")},
    };

    for (size_t i = 0; i < S_COUNT(path); i++) {
        if (!path[i].env)
            continue;

        int ret = snprintf(s.path, sizeof(s.path), path[i].fmt, path[i].env);

        if (ret <= 0 || (size_t)ret >= sizeof(s.path))
            s_fatal("Invalid path... Check $HOME or $" S_ENV_STORE);
        break;
    }
}

static int
s_version(int argc, char **argv, void *data)
{
    if (argz_help(argc, argv) || argc != 1) {
        if (isatty(1))
            printf("Usage: %s\n", argv[0]);
        return 0;
    }
    printf("%u.%u\n", S_VER_MAJOR, S_VER_MINOR);
    return 0;
}

int
main(int argc, char **argv)
{
    hydro_init();

    s_set_path();
    s_set_signals();

    enum s_op s_new = s_op_create | s_op_generate;
    enum s_op s_set = s_op_create;
    enum s_op s_rnw = s_op_generate;
    enum s_op s_rst = 0;

    struct argz mainz[] = {
        {"init",    "Initialize secret for the current user",      &s_init, .grp = 1},
        {"list",    "List all secrets for a given passphrase",     &s_list, .grp = 1},
        {"show",    "Print a secret",                  &s_show,    NULL,    .grp = 1},
        {"new",     "Generate a new secret",           &s_do,      &s_new,  .grp = 1},
        {"set",     "Set a new secret",                &s_do,      &s_set,  .grp = 1},
        {"renew",   "Regenerate an existing secret",   &s_do,      &s_rnw,  .grp = 1},
        {"reset",   "Update an existing secret",       &s_do,      &s_rst,  .grp = 1},
        {"pass",    "Derivate a new secret",           &s_pass,    NULL,    .grp = 1},
        {"agent",   "Run a process in a trusted zone", &s_agent,   NULL,    .grp = 1},
        {"version", "Show version",                    &s_version, NULL,    .grp = 1},
        {0}};

    if (argc == 1) {
        printf("Available commands:\n");
        argz_print(mainz);
    } else {
        int ret = argz(argc, argv, mainz);
        hydro_memzero(&s.x, sizeof(s.x));
        return ret;
    }
}
