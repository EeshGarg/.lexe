/* oracle.h -- the behavioural oracle shared by every .LEXE workload specimen.
 *
 * Contract with the consumer (Role B):
 *
 *   Every specimen writes KEY=VALUE lines, one per line, LF-terminated.
 *   - A line whose key does NOT start with "OBS_" is DETERMINISTIC. It must
 *     match the baseline byte for byte.
 *   - A line whose key starts with "OBS_" is an OBSERVATION: its value is
 *     environment-dependent (pid, path, duration, kernel detail). Compare only
 *     if you know why. Never treat a differing OBS_ line as a failure on its
 *     own.
 *   - The last stdout line of a specimen that reaches its own end is
 *     RESULT=PASS or RESULT=FAIL. RESULT=FAIL means the specimen's own
 *     self-check failed -- the program ran, and reported that its environment
 *     did not behave as the specimen requires. Absence of any RESULT line means
 *     the specimen did not reach its end (crash, signal, timeout).
 *   - A specimen that expects to die (crash/abort/signal) says so with
 *     EXPECT_DEATH=<how> before dying, so a missing RESULT line is still
 *     distinguishable from an accident.
 *
 * Nothing in here calls anything that is not in POSIX + glibc, and nothing
 * here depends on the compiler or optimisation level.
 */
#ifndef LEXE_ORACLE_H
#define LEXE_ORACLE_H

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ORC_UNUSED __attribute__((unused))

static int orc_failures ORC_UNUSED = 0;

ORC_UNUSED static void orc_begin(const char *id) {
    /* Line buffering makes ordering within each stream deterministic even when
     * the stream is a pipe rather than a terminal. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    printf("FIXTURE_ID=%s\n", id);
}

ORC_UNUSED static void orc_kv(const char *key, const char *fmt, ...) {
    va_list ap;
    printf("%s=", key);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

/* An environment-dependent observation. */
ORC_UNUSED static void orc_obs(const char *key, const char *fmt, ...) {
    va_list ap;
    printf("OBS_%s=", key);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

ORC_UNUSED static void orc_ekv(const char *key, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s=", key);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* Symbolic errno names, hand-tabled rather than taken from strerrorname_np, so
 * that the emitted text does not depend on the libc version or the compiler's
 * feature macros. */
ORC_UNUSED static const char *orc_errno_name(int e) {
    switch (e) {
    case 0:            return "NONE";
    case EACCES:       return "EACCES";
    case EPERM:        return "EPERM";
    case EROFS:        return "EROFS";
    case ENOENT:       return "ENOENT";
    case EEXIST:       return "EEXIST";
    case EAGAIN:       return "EAGAIN";
    case EBUSY:        return "EBUSY";
    case EINVAL:       return "EINVAL";
    case ENOMEM:       return "ENOMEM";
    case ENOSPC:       return "ENOSPC";
    case EMFILE:       return "EMFILE";
    case ENFILE:       return "ENFILE";
    case ENOSYS:       return "ENOSYS";
    case EPIPE:        return "EPIPE";
    case ENOTSUP:      return "ENOTSUP";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ENETUNREACH:  return "ENETUNREACH";
    case ENETDOWN:     return "ENETDOWN";
    case EADDRNOTAVAIL:return "EADDRNOTAVAIL";
    case EADDRINUSE:   return "EADDRINUSE";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case EXDEV:        return "EXDEV";
    case ELOOP:        return "ELOOP";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case EISDIR:       return "EISDIR";
    case ENOTDIR:      return "ENOTDIR";
    case ESRCH:        return "ESRCH";
    case ECHILD:       return "ECHILD";
    case EINTR:        return "EINTR";
    case ETIMEDOUT:    return "ETIMEDOUT";
    case EBADF:        return "EBADF";
    default:           return "EOTHER";
    }
}

/* A named boolean requirement of the specimen itself. Deterministic. */
ORC_UNUSED static int orc_check(const char *key, int ok) {
    printf("%s=%s\n", key, ok ? "yes" : "no");
    if (!ok) orc_failures++;
    return ok;
}

ORC_UNUSED static void orc_expect_death(const char *how) {
    printf("EXPECT_DEATH=%s\n", how);
    fflush(stdout);
}

/* FNV-1a, so a specimen can attest to a byte stream without printing it. */
ORC_UNUSED static unsigned long orc_fnv1a(const unsigned char *p, size_t n) {
    unsigned long h = 14695981039346656037UL;
    size_t i;
    for (i = 0; i < n; i++) { h ^= (unsigned long)p[i]; h *= 1099511628211UL; }
    return h;
}

ORC_UNUSED static int orc_end(void) {
    printf("RESULT=%s\n", orc_failures == 0 ? "PASS" : "FAIL");
    fflush(stdout);
    fflush(stderr);
    return 0;
}

#endif /* LEXE_ORACLE_H */
