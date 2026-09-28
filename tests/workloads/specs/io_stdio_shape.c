/* What ARE my three standard streams?
 *
 * Every other I/O specimen in this corpus varies what the program writes. This
 * one varies nothing: it is compiled once and launched through every stdio shape
 * the generator knows how to build -- a pipe, a regular file, `tee`, a command
 * substitution, a consumer that closes early, /dev/null on stdin, a regular file
 * on stdin, and with fd 1 closed outright. The shape is the variable; the
 * program is the constant.
 *
 * That is what makes the family a matrix instead of eight near-duplicates: the
 * same source reports a DIFFERENT deterministic answer under each shape, and the
 * difference is the measurement. A pipe and /dev/null both yield zero bytes on
 * stdin, so byte count alone cannot tell them apart -- STDIN_KIND can (fifo
 * versus chardev), and that is exactly the distinction a launcher gets wrong
 * when it "connects stdin" by handing over an empty pipe it never closes.
 *
 * The oracle is on STDERR, in full, because stdout is under test here and in one
 * shape is not open at all. Nothing about stdout is asserted with orc_check:
 * WRITE_STDOUT=EBADF is a correct and declared answer for the closed-fd shape,
 * not a failure. The specimen only fails if it contradicts itself.
 *
 * The stdout payload is printable ASCII and ends with a newline, deliberately:
 *   - printable, so a shell command substitution does not mangle it for reasons
 *     unrelated to the property under test (binary and NULs are covered by
 *     linux-io-binary-* instead);
 *   - ending in a newline, so the ONE transformation a command substitution
 *     performs -- stripping trailing newlines -- is visible and can be declared
 *     rather than discovered.
 *
 * The payload is framed by a delimiter line at both ends. It is found by that
 * frame and never by a byte offset: the stream also carries nothing derived from
 * the environment here, but the rule holds corpus-wide because an offset that
 * counted an environment-derived header line once moved a value that had been
 * declared deterministic.
 */
#include "oracle.h"
#include "orc_bulk.h"

#include <sys/stat.h>
#include <unistd.h>

#define PAYLOAD_BYTES 4096u
#define DELIM "<<<LEXE-STDIO-SHAPE-PAYLOAD>>>"

/* A regular file, a pipe, a character device and a socket are four different
 * things to a program even when all four deliver the same bytes. */
static const char *fd_kind(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0)
        return errno == EBADF ? "closed" : "unstattable";
    if (S_ISFIFO(st.st_mode)) return "fifo";
    if (S_ISREG(st.st_mode))  return "regular";
    if (S_ISCHR(st.st_mode))  return "chardev";
    if (S_ISSOCK(st.st_mode)) return "socket";
    if (S_ISDIR(st.st_mode))  return "directory";
    return "other";
}

/* Not named `yn`: that is a built-in (the Bessel function of the second kind,
 * double yn(int, double)), and shadowing it costs a -Wbuiltin-declaration-mismatch
 * warning in a corpus whose index records that every specimen compiled clean. */
static const char *orc_yesno(int v) { return v ? "yes" : "no"; }

/* Seekability is the property that distinguishes "my output is a file somebody
 * can rewind" from "my output is gone the moment it is read". */
static int seekable(int fd) {
    return lseek(fd, 0, SEEK_CUR) != (off_t)-1;
}

static void report_fd(const char *name, int fd) {
    char key[64];
    int flags = fcntl(fd, F_GETFL);
    snprintf(key, sizeof key, "%s_KIND", name);
    orc_ekv(key, "%s", fd_kind(fd));
    snprintf(key, sizeof key, "%s_ISATTY", name);
    orc_ekv(key, "%s", orc_yesno(isatty(fd)));
    snprintf(key, sizeof key, "%s_SEEKABLE", name);
    orc_ekv(key, "%s", orc_yesno(seekable(fd)));
    snprintf(key, sizeof key, "%s_OPEN", name);
    orc_ekv(key, "%s", orc_yesno(flags != -1));
    snprintf(key, sizeof key, "%s_APPEND", name);
    orc_ekv(key, "%s", orc_yesno(flags != -1 && (flags & O_APPEND)));
}

int main(void) {
    static unsigned char payload[PAYLOAD_BYTES];
    orb_sha256 sha;
    char hex[65];
    const char *id = getenv("FIXTURE_ID");
    unsigned long long total = 0;
    unsigned char inbuf[8192];
    ssize_t n;
    int read_errno = 0;
    size_t i;
    ssize_t w;
    int write_errno = 0;
    unsigned long long written = 0;
    int self_consistent = 1;

    setvbuf(stderr, NULL, _IOLBF, 0);
    orc_ekv("FIXTURE_ID", "%s", id ? id : "linux-stdio-shape");

    report_fd("STDIN", 0);
    report_fd("STDOUT", 1);
    report_fd("STDERR", 2);

    /* Deterministic printable filler: a byte is a pure function of its offset,
     * so the payload is identical on every host and at every -O level. */
    for (i = 0; i < PAYLOAD_BYTES; i++)
        payload[i] = (unsigned char)(0x20 + ((i * 7u + (i >> 5)) % 95u));
    payload[PAYLOAD_BYTES - 1] = '\n';

    orb_sha256_init(&sha);
    orb_sha256_update(&sha, (const uint8_t *)DELIM "\n", sizeof(DELIM));
    orb_sha256_update(&sha, payload, PAYLOAD_BYTES);
    orb_sha256_update(&sha, (const uint8_t *)DELIM "\n", sizeof(DELIM));
    orb_sha256_final(&sha, hex);

    /* Write straight to fd 1 with no stdio buffering in the way, so the claim
     * below is about what the kernel was asked to accept and nothing else. */
    w = write(1, DELIM "\n", sizeof(DELIM));
    if (w < 0) write_errno = errno; else written += (unsigned long long)w;
    if (w >= 0) {
        size_t off = 0;
        while (off < PAYLOAD_BYTES) {
            w = write(1, payload + off, PAYLOAD_BYTES - off);
            if (w <= 0) { write_errno = errno; break; }
            off += (size_t)w;
            written += (unsigned long long)w;
        }
        if (w > 0) {
            w = write(1, DELIM "\n", sizeof(DELIM));
            if (w < 0) write_errno = errno;
            else written += (unsigned long long)w;
        }
    }
    orc_ekv("WRITE_STDOUT", "%s", write_errno ? orc_errno_name(write_errno) : "ok");
    orc_ekv("STDOUT_PAYLOAD_DELIMITER", "%s", DELIM);
    orc_ekv("STDOUT_CLAIMED_SHA256", "%s", hex);
    /* A count over the stream the specimen itself wrote, reported so the runner
     * can compare like with like. It is NOT how the payload is located. */
    orc_ekv("STDOUT_CLAIMED_BYTES", "%llu",
            (unsigned long long)(PAYLOAD_BYTES + 2 * sizeof(DELIM)));
    /* NOT orc_obs(): that helper writes to STDOUT, and stdout is the stream under
     * test here. Emitting one observation through it appended 31 bytes to the
     * payload and broke the specimen's own digest -- caught by the attestation,
     * which is what attestations are for. Every oracle line in this specimen goes
     * to stderr; the OBS_ prefix, not the file descriptor, is what makes a line
     * an observation. */
    orc_ekv("OBS_STDOUT_BYTES_ACCEPTED", "%llu", written);

    /* Now stdin, to EOF. Zero bytes is a legitimate answer for several shapes;
     * WHY it is zero is what STDIN_KIND above distinguishes. */
    while ((n = read(0, inbuf, sizeof inbuf)) > 0)
        total += (unsigned long long)n;
    if (n < 0) read_errno = errno;
    orc_ekv("STDIN_BYTES", "%llu", total);
    orc_ekv("READ_STDIN", "%s", read_errno ? orc_errno_name(read_errno) : "ok");
    orc_ekv("STDIN_AT_EOF", "%s", orc_yesno(n == 0));

    /* The only self-checks: internal consistency, never a property of the shape.
     * A closed stdout, an empty stdin and a lost trailing newline are all
     * correct answers that the generator declares per shape. */
    if (!write_errno && written != (unsigned long long)(PAYLOAD_BYTES + 2 * sizeof(DELIM)))
        self_consistent = 0;
    if (write_errno && written != 0 && written >= PAYLOAD_BYTES)
        self_consistent = 0;
    orc_ekv("SELF_CONSISTENT", "%s", orc_yesno(self_consistent));
    orc_ekv("RESULT", "%s", self_consistent ? "PASS" : "FAIL");
    fflush(stderr);
    return self_consistent ? 0 : 1;
}
