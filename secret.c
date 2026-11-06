#define _GNU_SOURCE
#include "libhydrogen/hydrogen.c"

#include <stdint.h>
#include <string.h>

#ifdef NOMAIN
#define S_EXPORT(name) __attribute__((export_name(name)))
#else
#define S_EXPORT(name) static
#endif

#ifndef NOMAIN
#include "argz/argz.c"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#ifdef __FreeBSD__
#include <sys/procctl.h>
#endif

#ifdef __APPLE__
#define PT_DENY_ATTACH 31
extern int ptrace(int, pid_t, char *, int);
#endif
#endif

#define S_COUNT(x)  (sizeof(x) / sizeof((x)[0]))
#define S_VER_MAJOR  0U
#define S_VER_MINOR  21U
#define S_ENTRYSIZE  512U
#define S_PWDGENLEN  25U
#define S_KEYLENMAX  255U
#define S_OPS_LIMIT  10000U
#define S_ENV_AGENT "SECRET_AGENT"
#define S_ENV_STORE "SECRET_STORE"

struct s_key {
    uint8_t b[hydro_secretbox_KEYBYTES];
};

struct s_secret {
    const char *name;
    const uint8_t *value;
    size_t len;
};

struct s_totp {
    char b[7];
};

_Static_assert(hydro_pwhash_MASTERKEYBYTES == hydro_secretbox_KEYBYTES, "");

static struct {
    char path[1024];
    struct {
        struct {
            uint8_t version;
            struct s_key master;
            uint8_t ops_limit[8];
        } hdr;
        struct s_key key;
    } x;
    struct {
        uint8_t slen[2];
        uint8_t data[S_ENTRYSIZE - hydro_secretbox_HEADERBYTES - 2U];
    } entry;
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

static int
s_derive(struct s_key *out, void *pass, size_t len, const char *ctx,
         const struct s_key *key)
{
    return hydro_pwhash_deterministic(out->b, sizeof(out->b),
                                      pass, len, ctx, key->b,
                                      load64_le(s.x.hdr.ops_limit), 0, 1);
}

S_EXPORT("secret_header") int
s_header(const void *buf)
{
    memcpy(&s.x.hdr, buf, sizeof(s.x.hdr));

    if (s.x.hdr.version != S_VER_MAJOR)
        return 1;

    if (load64_le(s.x.hdr.ops_limit) < S_OPS_LIMIT)
        return 2;

    return 0;
}

S_EXPORT("secret_unlock") int
s_unlock(void *pass, size_t len)
{
    int ret = s_derive(&s.x.key, pass, len, s.ctx_master, &s.x.hdr.master);
    hydro_memzero(pass, len);
    return ret;
}

S_EXPORT("secret_lock") void
s_lock(void)
{
    hydro_memzero(&s.x.key, sizeof(s.x.key));
    hydro_memzero(&s.entry, sizeof(s.entry));
    hydro_memzero(s.enc, sizeof(s.enc));
    s.pass_ok = 0;
}

S_EXPORT("secret_decrypt") const void *
s_decrypt(const void *buf)
{
    return hydro_secretbox_decrypt(&s.entry, buf, S_ENTRYSIZE, 0,
                                   s.ctx_secret, s.x.key.b) ? NULL : &s.entry;
}

#ifndef NOMAIN
_Noreturn static void
s_exit(int code)
{
    s_lock();
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
#endif

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

    hydro_memzero(w, sizeof(w));
}

static void
s_sha1(uint8_t *digest, const uint8_t *buf, size_t len)
{
    uint8_t tmp[64] = {0};
    uint32_t x[] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    s_sha1_process(buf, x);
    memcpy(tmp, buf + 64, len - 64);
    tmp[len - 64] = 0x80;
    store64_be(tmp + 56, len << 3);
    s_sha1_process(tmp, x);

    for (int i = 0; i < 5; i++)
        store32_be(&digest[i << 2], x[i]);

    hydro_memzero(tmp, sizeof(tmp));
    hydro_memzero(x, sizeof(x));
}

S_EXPORT("secret_totp") struct s_totp
s_totp(struct s_secret secret, uint64_t counter)
{
    struct s_totp out = {0};

    if (!secret.len || secret.len > 64)
        return out;

    uint8_t h[20];
    uint8_t ki[64 +  8] = {0};
    uint8_t ko[64 + 20] = {0};

    memcpy(ki, secret.value, secret.len);
    memcpy(ko, secret.value, secret.len);

    for (int i = 0; i < 64; i++) {
        ki[i] ^= 0x36;
        ko[i] ^= 0x5c;
    }
    store64_be(&ki[64], counter);
    s_sha1(&ko[64], ki, sizeof(ki));
    s_sha1(h, ko, sizeof(ko));

    hydro_memzero(ki, sizeof(ki));
    hydro_memzero(ko, sizeof(ko));

    uint32_t ret = (load32_be(&h[h[19] & 0xF]) & ~(UINT32_C(1) << 31))
                 % UINT32_C(1000000);

    hydro_memzero(h, sizeof(h));

    for (size_t i = sizeof(out.b) - 1; i--; ret /= 10)
        out.b[i] = '0' + ret % 10;

    return out;
}

static int
s_b32(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    } else if (c >= '2' && c <= '7') {
        return c - '2' + ('Z' - 'A') + 1;
    }
    return -1;
}

S_EXPORT("secret_totp32") struct s_totp
s_totp32(struct s_secret secret, uint64_t counter)
{
    struct s_totp ret = {0};
    uint8_t out[64];
    size_t outlen = 0;
    unsigned buf = 0;
    int bits = 0;

    for (int i = 0; i < secret.len; i++) {
        uint8_t c = secret.value[i];

        if (!c || c == '=' || c == '\n')
            break;

        int v = s_b32(c);

        if (v < 0)
            goto done;

        buf = (buf << 5) | (unsigned)v;
        bits += 5;

        if (bits < 8)
            continue;

        if (outlen == sizeof(out) - 1)
            goto done;

        bits -= 8;
        out[outlen++] = (buf >> bits) & 0xFF;
    }
    if (bits)
        out[outlen++] = (buf << (8 - bits)) & 0xFF;

    struct s_secret decoded = {
        .name = secret.name,
        .value = out,
        .len = outlen,
    };
    ret = s_totp(decoded, counter);

done:
    hydro_memzero(out, sizeof(out));
    return ret;
}

#ifndef NOMAIN
static int
s_printable(const uint8_t *buf, size_t len)
{
    size_t pos = 0;

    while (pos < len) {
        uint8_t c = buf[pos++];

        if ((c >= ' ' && c <= '~') || c == '\n' || c == '\t')
            continue;

        if (c < 0xc2 || c > 0xf4)
            return 0;

        unsigned n = 1u + (c >= 0xc2) + (c >= 0xe0) + (c >= 0xf0);

        for (unsigned i = 1; i < n; i++) {
            if (pos == len || buf[pos++] - 0x80u > 0x3f)
                return 0;
        }
    }
    return 1;
}

static size_t
s_read(int fd, void *data, size_t size)
{
    size_t done = 0;
    struct pollfd pfd = {.fd = fd, .events = POLLIN};

    while (done < size) {
        ssize_t r = read(fd, (uint8_t *)data + done, size - done);
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
        ssize_t r = write(fd, (const uint8_t *)data + done, size - done);
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
s_input(uint8_t *buf, size_t size, const char *prompt)
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
s_ask_pass(const char *prompt)
{
    uint8_t pass[128];
    size_t len = s_input(pass, sizeof(pass), prompt);

    if (!len)
        s_exit(0);

    if (s_unlock(pass, len))
        s_fatal("s_ask_pass() failed");
}

static int
s_ask_agent(void)
{
    const char *agent = getenv(S_ENV_AGENT);

    if (!agent)
        return 1;

    errno = 0;
    char *end = NULL;
    long fd = strtol(agent, &end, 10);

    if (errno || end == agent || *end || fd < 0 || fd > INT_MAX)
        return 1;

    int match = recv((int)fd, s.enc, sizeof(s.enc), MSG_PEEK | MSG_DONTWAIT)
        == (ssize_t)sizeof(s.x)
        && !memcmp(s.enc, &s.x.hdr, sizeof(s.x.hdr));

    if (match) {
        memcpy(&s.x, s.enc, sizeof(s.x));
    } else {
        hydro_memzero(&s.x.key, sizeof(s.x.key));
    }
    hydro_memzero(s.enc, sizeof(s.enc));
    s.pass_ok = match;
    return !match;
}

static int
s_open_secret(int use_tty, int flags)
{
    int fd = open(s.path, flags);

    if (fd == -1) switch (errno) {
        case ENOENT: s_fatal("Secret store %s doesn't exist", s.path);
        default:     s_fatal("%s: %s", s.path, strerror(errno));
    }
    if (s_read(fd, s.enc, sizeof(s.enc)) != sizeof(s.enc))
        s_fatal("Unable to read %s", s.path);

    switch (s_header(s.enc)) {
        case 1: s_fatal("Unkown version %" PRIu8, s.x.hdr.version);
        case 2: s_fatal("Store opslimit is below the minimum of %u", S_OPS_LIMIT);
    }
    if (!s_ask_agent())
        return fd;

    if (!use_tty)
        s_exit(0);

    s_ask_pass("Passphrase: ");
    return fd;
}

static void
s_print_keys(const char *needle, int use_tty)
{
    int fd = s_open_secret(use_tty, O_RDONLY);

    while (s_read(fd, s.enc, sizeof(s.enc)) == sizeof(s.enc)) {
        if (!s_decrypt(s.enc))
            continue;

        const char *key = (const char *)s.entry.data;
        size_t len = s_keylen(key);

        if (!needle || strcasestr(key, needle)) {
            s_write(1, key, len);
            s_write(1, "\n", 1);
        }
        hydro_memzero(&s.entry, sizeof(s.entry));
    }
    close(fd);
}

static struct s_secret
s_get_secret(int fd, const char *key, int create)
{
    size_t len = key ? s_keylen(key) : 0;
    off_t slot = 0;

    while (s_read(fd, s.enc, sizeof(s.enc)) == sizeof(s.enc)) {
        if (!s_decrypt(s.enc))
            continue;

        if (create && !slot && hydro_equal(s.entry.data, "DELETED:", 8))
            slot = lseek(fd, 0, SEEK_CUR) - (off_t)sizeof(s.enc);

        if (key && hydro_equal(s.entry.data, key, len + 1)) {
            if (create)
                s_fatal("Secret %s exists!", key);
            if (lseek(fd, -(off_t)sizeof(s.enc), SEEK_CUR) == (off_t)-1)
                s_fatal("seek: %s", strerror(errno));
            struct s_secret ret = {
                .name = (const char *)s.entry.data,
                .value = s.entry.data + len + 1,
                .len = load16_le(s.entry.slen),
            };
            if (ret.len > sizeof(s.entry.data) - len - 1)
                s_fatal("Invalid secret");
            return ret;
        }
        s.pass_ok = 1;
        hydro_memzero(&s.entry, sizeof(s.entry));
    }
    if (key && !create)
        s_fatal("Secret %s not found", key);

    if (s.pass_ok) {
        if (slot)
            lseek(fd, slot, SEEK_SET);
        return (struct s_secret){0};
    }
    struct s_key check = s.x.key;
    s_ask_pass("No secrets stored with this passphrase.\n"
               "Please, retype it to confirm: ");

    if (!hydro_equal(&s.x.key, &check, sizeof(check)))
        s_fatal("Passphrases don't match!");

    s.pass_ok = 1;
    return (struct s_secret){0};
}

static void
s_set_secret(int fd, const char *key, const uint8_t *secret, size_t slen)
{
    size_t len = s_keylen(key);

    if (len + slen + 1 > sizeof(s.entry.data))
        s_fatal("Entry too big!");

    store16_le(s.entry.slen, slen);

    size_t t = 0;
    memcpy(s.entry.data, key, len);          t += len;
    s.entry.data[t] = 0;                     t += 1;
    memcpy(s.entry.data + t, secret, slen);  t += slen;
    hydro_random_buf(s.entry.data + t, sizeof(s.entry.data) - t);
    hydro_secretbox_encrypt(s.enc, &s.entry, sizeof(s.entry), 0,
                            s.ctx_secret, s.x.key.b);
    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_CUR,
        .l_len = (off_t)sizeof(s.enc),
    };
    if (fcntl(fd, F_SETLK, &fl))
        s_fatal("Unable to lock %s", s.path);
    s_write(fd, s.enc, sizeof(s.enc));
    hydro_memzero(&s.entry, sizeof(s.entry));
}

static int
s_init(int argc, char **argv, void *data)
{
    struct argz_ull ops_limit = {
        .min   = S_OPS_LIMIT,
        .value = S_OPS_LIMIT * 10U,
    };
    struct argz z[] = {
        {"opslimit", "Number of iterations to perform", argz_ull, &ops_limit},
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
    s.x.hdr.version = S_VER_MAJOR;
    hydro_random_buf(&s.x.hdr.master, sizeof(s.x.hdr.master));
    store64_le(s.x.hdr.ops_limit, (uint64_t)ops_limit.value);
    memset(s.enc, 0, sizeof(s.enc));
    memcpy(s.enc, &s.x.hdr, sizeof(s.x.hdr));
    s_write(fd, s.enc, sizeof(s.enc));
    hydro_memzero(s.enc, sizeof(s.enc));
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
s_normalize_and_show(uint8_t *buf, size_t size)
{
    const unsigned n = 1U + '~' - '!';
    size_t k = 0;

    for (size_t i = 0; i < size && k < S_PWDGENLEN; i++) {
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
    struct s_secret old = s_get_secret(fd, argv[1], op & s_op_create);
    uint8_t secret[S_ENTRYSIZE];
    size_t len = 0;

    if (op & s_op_generate) {
        hydro_random_buf(secret, sizeof(secret));
        len = s_normalize_and_show(secret, sizeof(secret));
    } else {
        len = isatty(0) ? s_input(secret, sizeof(secret), "Secret: ")
                        : s_read(0, secret, sizeof(secret));
        if (!len && old.value && argc == 3) {
            len = old.len;
            memcpy(secret, old.value, len);
        }
    }
    if (!len)
        s_exit(0);

    s_set_secret(fd, argv[argc - 1], secret, len);
    close(fd);
    hydro_memzero(secret, sizeof(secret));
    return 0;
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
    struct s_secret out = s_get_secret(fd, argv[1], 0);
    close(fd);

    if (!dump && strstr(out.name, "totp")) {
        uint64_t counter = (uint64_t)time(NULL) / 30;
        struct s_totp totp = strstr(out.name, "totp32")
                           ? s_totp32(out, counter) : s_totp(out, counter);
        if (!totp.b[0])
            s_fatal("Invalid secret");

        s_write(1, totp.b, 6);
        hydro_memzero(&totp, sizeof(totp));
    } else if (isatty(1) && !s_printable(out.value, out.len)) {
        for (size_t i = 0; i < out.len; i += 3) {
            size_t n = out.len - i < 3 ? out.len - i : 3;
            uint32_t v = 0;
            char enc[4] = "====";

            for (size_t j = 0; j < n; j++)
                v = (v << 8) | out.value[i + j];

            v <<= 8 * (3 - n);

            for (size_t j = 0; j <= n; j++)
                enc[j] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "abcdefghijklmnopqrstuvwxyz"
                         "0123456789+/"[v >> (18 - 6 * j) & 63];

            s_write(1, enc, sizeof(enc));
        }
    } else {
        s_write(1, out.value, out.len);
    }
    if (isatty(1)) s_write(1, "\n", 1);
    hydro_memzero(&s.entry, sizeof(s.entry));
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

    struct s_key buf, key = s.x.key;

    for (int i = 1; i < argc; i++) {
        if (s_derive(&buf, argv[i], s_keylen(argv[i]), s.ctx_passwd, &key))
            s_fatal("s_pass() failed");
        key = buf;
    }
    s_normalize_and_show(buf.b, sizeof(buf.b));
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

    char *shell = argv[1];

    if (!shell)
        shell = getenv("SHELL");

    if (!shell)
        s_fatal("Missing env SHELL, nothing to exec!");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv))
        s_fatal("socketpair: %s", strerror(errno));

    int fd = s_open_secret(1, O_RDONLY);
    s_get_secret(fd, NULL, 0);
    close(fd);

    if (send(sv[1], &s.x, sizeof(s.x), 0) != (ssize_t)sizeof(s.x))
        s_fatal("Unable to queue the key");

    hydro_memzero(&s, sizeof(s));
    close(sv[1]);

    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%d", sv[0]);
    setenv(S_ENV_AGENT, tmp, 1);

    char *args[] = {shell, NULL};
    execvp(shell, argv[1] ? argv + 1 : args);
    s_fatal("%s: %s", shell, strerror(errno));
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

static void
s_handler(int sig)
{
    (void)sig;
}

static void
s_set_notrace(void)
{
#if defined(__linux__)
    if (prctl(PR_SET_DUMPABLE, 0L) == -1)
        s_fatal("prctl: %s", strerror(errno));
#elif defined(__FreeBSD__)
    int mode = PROC_TRACE_CTL_DISABLE_EXEC;
    if (procctl(P_PID, 0, PROC_TRACE_CTL, &mode) == -1)
        s_fatal("procctl: %s", strerror(errno));
#elif defined(__APPLE__)
    if (ptrace(PT_DENY_ATTACH, 0, NULL, 0) == -1)
        s_fatal("ptrace: %s", strerror(errno));
#endif
}

static void
s_set_signals(void)
{
    int sig[] = {
        SIGHUP,  SIGINT,  SIGQUIT, SIGUSR1,
        SIGUSR2, SIGPIPE, SIGALRM, SIGTERM,
    };
    struct sigaction sa = {
        .sa_handler = s_handler,
    };
    sigemptyset(&sa.sa_mask);

    for (size_t i = 0; i < S_COUNT(sig); i++)
        sigaction(sig[i], &sa, NULL);
}

int
main(int argc, char **argv)
{
    hydro_init();
    s_set_notrace();
    s_set_signals();
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
    s_exit(argz_main(argc, argv, z));
}
#endif
