#include "argz/argz.c"
#include "libhydrogen/hydrogen.c"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define S_COUNT(x)  (sizeof(x) / sizeof((x)[0]))
#define S_VER_MAJOR  0U
#define S_VER_MINOR  16U
#define S_ENTRYSIZE  512U
#define S_PWDGENLEN  25U
#define S_KEYLENMAX  255U
#define S_ENV_AGENT "SECRET_AGENT"
#define S_ENV_STORE "SECRET_STORE"

static struct {
    char path[1024];
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
    int pass_ok;
} s = {
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
    char tmp[256] = "Fatal: ";
    char *buf = &tmp[7];
    size_t size = sizeof(tmp) - 7;

    va_start(ap, fmt);
    int ret = vsnprintf(buf, size, fmt, ap);
    va_end(ap);

    if (ret <= 0)
        s_exit(1);

    if (size <= (size_t)ret)
        ret = size - 1;

    buf[ret] = '\n';
    (void)!write(2, tmp, ret + 8);
    s_exit(1);
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
            case EAGAIN: if (poll(&pfd, 1, 200) < 1) return done; /* FALLTHRU */
            case EINTR:  continue;
            default:     return done;
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
            case EAGAIN: if (poll(&pfd, 1, 200) < 1) return done; /* FALLTHRU */
            case EINTR:  continue;
            default:     return done;
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

    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
    };
    if (fcntl(fd, F_SETLKW, &fl))
        s_fatal("Unable to lock %s", tty);

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
    if (r) s_fatal("s_ask_pass() failed");
}

static int
s_ask_agent(void)
{
    const char *agent = getenv(S_ENV_AGENT);
    int wfd = -1, rfd = -1;

    if (!agent || sscanf(agent, "%d.%d", &wfd, &rfd) != 2 || wfd < 0 || rfd < 0)
        return 1;

    s_write(wfd, "", 1);

    if (s_read(rfd, s.x.key, sizeof(s.x.key)) != sizeof(s.x.key))
        return 1;

    s.pass_ok = 1;
    return 0;
}

static int
s_open_secret(int use_tty, int flags)
{
    int fd = open(s.path, flags);

    if (fd == -1) switch (errno) {
        case ENOENT: s_fatal("Secret store %s doesn't exist", s.path);
        default:     s_fatal("%s: %s", s.path, strerror(errno));
    }
    if (s_read(fd, s.hdr.buf, sizeof(s.hdr.buf)) != sizeof(s.hdr.buf))
        s_fatal("Unable to read %s", s.path);

    if (s.hdr.version != S_VER_MAJOR)
        s_fatal("Unkown version %" PRIu8, s.hdr.version);

    if (!s_ask_agent())
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
s_print_keys(const char *needle, int use_tty)
{
    int fd = s_open_secret(use_tty, O_RDONLY);

    while (s_read(fd, s.enc, sizeof(s.enc)) == sizeof(s.enc)) {
        if (hydro_secretbox_decrypt(&s.x.entry,
                                    s.enc, sizeof(s.enc), 0,
                                    s.ctx_secret, s.x.key))
            continue;

        size_t len = s_keylen(s.x.entry.msg);

        if (needle && !strcasestr(s.x.entry.msg, needle))
            continue;

        s_write(1, s.x.entry.msg, len);
        s_write(1, "\n", 1);
    }
    close(fd);
}

static const char *
s_get_secret(int fd, const char *key, int create)
{
    size_t len = key ? s_keylen(key) : 0;
    off_t slot = 0;

    while (s_read(fd, s.enc, sizeof(s.enc)) == sizeof(s.enc)) {
        if (hydro_secretbox_decrypt(&s.x.entry,
                                    s.enc, sizeof(s.enc), 0,
                                    s.ctx_secret, s.x.key))
            continue;

        if (create && !slot && hydro_equal(s.x.entry.msg, "DELETED:", 8))
            slot = lseek(fd, 0, SEEK_CUR) - (off_t)sizeof(s.enc);

        if (key && hydro_equal(s.x.entry.msg, key, len + 1)) {
            if (create)
                s_fatal("Secret %s exists!", key);
            if (lseek(fd, -(off_t)sizeof(s.enc), SEEK_CUR) == (off_t)-1)
                s_fatal("seek: %s", strerror(errno));
            return &s.x.entry.msg[len + 1];
        }
        s.pass_ok = 1;
    }
    if (key && !create)
        s_fatal("Secret %s not found", key);

    if (s.pass_ok) {
        if (slot)
            lseek(fd, slot, SEEK_SET);
        return NULL;
    }
    char check[sizeof(s.x.key)];
    s_ask_pass(check, sizeof(check),
            "No secrets stored with this passphrase.\n"
            "Please, retype it to confirm: ");

    if (!hydro_equal(s.x.key, check, sizeof(check)))
        s_fatal("Passphrases don't match!");

    s.pass_ok = 1;
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
    hydro_secretbox_encrypt(s.enc, &s.x.entry, sizeof(s.x.entry), 0,
                            s.ctx_secret, s.x.key);
    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_CUR,
        .l_len = (off_t)sizeof(s.enc),
    };
    if (fcntl(fd, F_SETLK, &fl))
        s_fatal("Unable to lock %s", s.path);

    s_write(fd, s.enc, sizeof(s.enc));
}

static int
s_init(int argc, char **argv, void *data)
{
    struct argz_ull opslimit = {
        .min = 100,
        .value = 10000,
    };
    struct argz z[] = {
        {"opslimit", "Number of iterations to perform", argz_ull, &opslimit},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    if (getenv(S_ENV_AGENT))
        s_fatal("Agent is running...");

    int fd = open(s.path, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (fd == -1) switch (errno) {
        case EEXIST: s_fatal("Secret store %s already exists", s.path);
        default:     s_fatal("%s: %s", s.path, strerror(errno));
    }
    s.hdr.version = S_VER_MAJOR;
    hydro_random_buf(s.hdr.master, sizeof(s.hdr.master));
    store64_le(s.hdr.opslimit, (uint64_t)opslimit.value);
    s_write(fd, s.hdr.buf, sizeof(s.hdr.buf));
    return 0;
}

static int
s_list(int argc, char **argv, void *data)
{
    if (argz_help(argc, argv) || argc > 2) {
        if (isatty(1))
            printf("Usage: %s [NEEDLE]\n", argv[0]);
        return -1;
    }
    s_print_keys(argv[1], 1);
    return 0;
}

static size_t
s_normalize_and_show(unsigned char *buf, size_t size, size_t want)
{
    const unsigned n = 1U + '~' - '!';
    size_t k = 0;

    for (size_t i = 0; i < size && k < want; i++) {
        if (buf[i] < 2 * n)
            buf[k++] = '!' + buf[i] % n;
    }
    s_write(1, buf, k);
    if (isatty(1)) s_write(1, "\n", 1);
    return k;
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
            s_print_keys(NULL, 0);
        }
        return -1;
    }
    int fd = s_open_secret(1, O_RDWR);
    const char *old = s_get_secret(fd, argv[1], op & s_op_create);
    unsigned char secret[S_ENTRYSIZE];
    size_t len = 0;

    if (op & s_op_generate) {
        hydro_random_buf(secret, sizeof(secret));
        len = s_normalize_and_show(secret, sizeof(secret), S_PWDGENLEN);
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

static void
s_sha1_process(const uint8_t *buf, uint32_t x[5])
{
    uint32_t w[80];
    uint32_t a = x[0], b = x[1], c = x[2], d = x[3], e = x[4];

    for (int i = 0; i < 16; i++)
        w[i] = load32_be(&buf[i << 2]);

    for (int i = 16; i < 80; i++)
        w[i] = ROTL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    for (int i = 0; i < 80; i++) {
        uint32_t t = ROTL32(a, 5) + e + w[i];
             if (i < 20) t += 0x5A827999 + ((b & c) | ((~b) & d));
        else if (i < 40) t += 0x6ED9EBA1 + (b ^ c ^ d);
        else if (i < 60) t += 0x8F1BBCDC + ((b & c) | (b & d) | (c & d));
        else             t += 0xCA62C1D6 + (b ^ c ^ d);
        e = d; d = c; c = ROTL32(b, 30); b = a; a = t;
    }
    x[0] += a; x[1] += b; x[2] += c; x[3] += d; x[4] += e;
}

static void
s_sha1(uint8_t *digest, uint8_t *buf, size_t len)
{
    uint8_t tmp[64] = {0};
    uint32_t x[] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    size_t p = 0;

    for (; p + 64 <= len; p += 64)
        s_sha1_process(buf + p, x);

    if (len > p)
        memcpy(tmp, buf + p, len - p);

    p = len - p;
    tmp[p++] = 0x80;

    if (p > 56) {
        s_sha1_process(tmp, x);
        memset(tmp, 0, sizeof(tmp));
    }
    store64_be(tmp + 56, len << 3);
    s_sha1_process(tmp, x);

    for (int i = 0; i < 5; i++)
        store32_be(&digest[i << 2], x[i]);
}

static void
s_totp(const char *secret, size_t len)
{
    if (!len || len > 64)
        return;

    uint8_t h[20];
    uint8_t ki[64 +  8] = {0};
    uint8_t ko[64 + 20] = {0};

    memcpy(ki, secret, len);
    memcpy(ko, secret, len);

    for (int i = 0; i < 64; i++) {
        ki[i] ^= 0x36;
        ko[i] ^= 0x5c;
    }
    store64_be(&ki[64], ((uint64_t)time(NULL)) / 30);
    s_sha1(&ko[64], ki, sizeof(ki));
    s_sha1(h, ko, sizeof(ko));

    hydro_memzero(ki, sizeof(ki));
    hydro_memzero(ko, sizeof(ko));

    uint32_t ret = (load32_be(&h[h[19] & 0xF]) & ~(UINT32_C(1) << 31))
                 % UINT32_C(1000000);
    char tmp[7];
    if (snprintf(tmp, sizeof(tmp), "%06" PRIu32, ret) == 6)
        s_write(1, tmp, 6);
}

static unsigned
s_b32(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    } else if (c >= '2' && c <= '7') {
        return c - '2' + ('Z' - 'A') + 1;
    }
    s_fatal("Invalid base32 character");
}

static void
s_totp32(const char *secret, size_t len)
{
    if (!len)
        return;

    char out[64];
    size_t outlen = 0;
    unsigned buf = 0;
    int bits = 0;

    for (int i = 0; i < len; i++) {
        char c = secret[i];

        if (!c || c == '=' || c == '\n')
            break;

        buf = (buf << 5) | s_b32(c);
        bits += 5;

        if (bits < 8)
            continue;

        if (outlen == 64)
            s_fatal("TOTP too big");

        bits -= 8;
        out[outlen++] = (buf >> bits) & 0xFF;
    }
    if (bits)
        out[outlen++] = (buf << (8 - bits)) & 0xFF;

    s_totp(out, outlen);
}

static int
s_show(int argc, char **argv, void *dump)
{
    if (argz_help(argc, argv) || argc != 2) {
        if (isatty(1)) {
            printf("Usage: %s KEY\n", argv[0]);
        } else if (argc == 2) {
            s_print_keys(NULL, 0);
        }
        return -1;
    }
    int fd = s_open_secret(1, O_RDONLY);
    const char *secret = s_get_secret(fd, argv[1], 0);

    if (secret) {
        size_t len = load16_le(s.x.entry.slen);
        if (!dump && strstr(argv[1], "totp32")) {
            s_totp32(secret, len);
        } else if (!dump && strstr(argv[1], "totp")) {
            s_totp(secret, len);
        } else {
            s_write(1, secret, len);
        }
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
        return -1;
    }
    int fd = s_open_secret(1, O_RDONLY);
    s_get_secret(fd, NULL, 0);
    close(fd);

    uint8_t buf[hydro_pwhash_MASTERKEYBYTES];
    uint8_t key[hydro_pwhash_MASTERKEYBYTES];
    memcpy(key, s.x.key, sizeof(key));

    for (int i = 1; i < argc; i++) {
        int r = hydro_pwhash_deterministic(buf, sizeof(buf),
                                           argv[i], s_keylen(argv[i]),
                                           s.ctx_passwd, key,
                                           load64_le(s.hdr.opslimit), 0, 1);
        if (r) s_fatal("s_pass() failed");
        memcpy(key, buf, sizeof(key));
    }
    s_normalize_and_show(buf, sizeof(buf), S_PWDGENLEN);
    return 0;
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
        return -1;
    }
    if (getenv(S_ENV_AGENT))
        s_fatal("Already running...");

    const char *shell = argv[1];

    if (!shell)
        shell = getenv("SHELL");

    if (!shell)
        s_fatal("Missing env SHELL, nothing to exec!");

    int fd = s_open_secret(1, O_RDONLY);
    s_get_secret(fd, NULL, 0);
    close(fd);

    int rfd[2], wfd[2];
    if (pipe(rfd) || pipe(wfd))
        s_fatal("pipe: %s", strerror(errno));

    pid_t child = fork();

    if (child == (pid_t)-1)
        s_fatal("fork: %s", strerror(errno));

    if (child) {
        close(rfd[0]);
        close(wfd[1]);
        hydro_memzero(&s.x, sizeof(s.x));

        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%d.%d", rfd[1], wfd[0]);
        setenv(S_ENV_AGENT, tmp, 1);

        execvp(shell, argv + 1);
        s_fatal("%s: %s", shell, strerror(errno));
    }
    close(rfd[1]);
    close(wfd[0]);

    if (setsid() == -1)
        s_fatal("setsid: %s", strerror(errno));

    char tmp;
    while (s_read(rfd[0], &tmp, 1) == 1) {
        if (s_write(wfd[1], s.x.key, sizeof(s.x.key)) != sizeof(s.x.key))
            return 1;
    }
    return 0;
}

static void
s_set_path(void)
{
    int ret;
    const char *store = getenv(S_ENV_STORE);
    const char *home = getenv("HOME");

    if (store && store[0]) {
        ret = snprintf(s.path, sizeof(s.path), "%s", store);
    } else {
        ret = snprintf(s.path, sizeof(s.path), "%s/.secret", home ? home : "");
    }
    if (ret <= 1 || (size_t)ret >= sizeof(s.path))
        s_fatal("Invalid path... Check $HOME or $" S_ENV_STORE);
}

static int
s_version(int argc, char **argv, void *data)
{
    int err = argz(argc, argv, NULL);

    if (err)
        return err;

    printf("%u.%u\n", S_VER_MAJOR, S_VER_MINOR);
    return 0;
}

int
main(int argc, char **argv)
{
    hydro_init();
    s_set_path();

    enum s_op s_new = s_op_create | s_op_generate;
    enum s_op s_set = s_op_create;
    enum s_op s_rnw = s_op_generate;
    enum s_op s_rst = 0;
    int dump = 1;

    struct argz z[] = {
        {"init",    "Initialize secret",                           &s_init, .grp = 1},
        {"list",    "List all secrets for a given passphrase",     &s_list, .grp = 1},
        {"show",    "Print a secret",                  &s_show,    NULL,    .grp = 1},
        {"dump",    "Dump a raw secret",               &s_show,    &dump,   .grp = 1},
        {"new",     "Generate a new random secret",    &s_do,      &s_new,  .grp = 1},
        {"set",     "Set a new secret",                &s_do,      &s_set,  .grp = 1},
        {"renew",   "Regenerate an existing secret",   &s_do,      &s_rnw,  .grp = 1},
        {"update",  "Update an existing secret",       &s_do,      &s_rst,  .grp = 1},
        {"pass",    "Print a deterministic secret",    &s_pass,    NULL,    .grp = 1},
        {"agent",   "Run a process in a trusted zone", &s_agent,   NULL,    .grp = 1},
        {"version", "Show version",                    &s_version, NULL,    .grp = 1},
        {0}};

    if (argc == 1) {
        argz_print(z);
        return 0;
    }
    int ret = argz_main(argc, argv, z);
    hydro_memzero(&s.x, sizeof(s.x));
    return ret;
}
