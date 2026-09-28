/* oracle_win.h -- the behavioural oracle for the Windows PE workload corpus.
 *
 * Same contract as specs/oracle.h (KEY=VALUE lines; OBS_ keys are
 * environment-dependent observations; RESULT=PASS|FAIL last; EXPECT_DEATH for
 * specimens that are meant to die), with one addition that the PE corpus cannot
 * do without:
 *
 *   EVERY LINE IS WRITTEN TWICE -- once to the stream, and once to an oracle
 *   FILE in the working directory.
 *
 * The reason is measured, not stylistic. Under Proton's own `proton run` entry
 * point the guest program's stdout and stderr are NOT delivered to the caller:
 * the exit code propagates, files it writes appear, but the console output is
 * gone. A GUI-subsystem PE has no console to write to in the first place. So a
 * corpus that reported only on stdout would be unobservable under exactly the
 * translation layer it most needs to be compared across.
 *
 * The file is therefore the layer-independent channel and the primary artifact;
 * the stream is compared only where the layer actually delivers it.
 *
 * The file is flushed after every line, so a specimen that crashes leaves
 * everything it managed to report up to the fault.
 *
 * This header compiles on Linux too, so the portable specimens (p_*.c) can be
 * built as a native ELF and as a PE from one source and compared.
 */
#ifndef LEXE_ORACLE_WIN_H
#define LEXE_ORACLE_WIN_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#endif

#define ORC_UNUSED __attribute__((unused))

static FILE *orc_file ORC_UNUSED = NULL;
static int orc_failures ORC_UNUSED = 0;
static const char *orc_id ORC_UNUSED = "unset";

ORC_UNUSED static void orc_begin(const char *id) {
    char path[512];
    const char *override_path = getenv("LEXE_ORACLE_FILE");
    const char *env_id = getenv("FIXTURE_ID");
    orc_id = (env_id && *env_id) ? env_id : id;
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    if (override_path && *override_path) {
        snprintf(path, sizeof path, "%s", override_path);
    } else {
        snprintf(path, sizeof path, "%s.oracle", orc_id);
    }
    orc_file = fopen(path, "w");
    printf("FIXTURE_ID=%s\n", orc_id);
    if (orc_file) {
        fprintf(orc_file, "FIXTURE_ID=%s\n", orc_id);
        fflush(orc_file);
    } else {
        printf("ORACLE_FILE_OPEN=fail\n");
    }
}

/* Like orc_begin, but the id is FIXED and the FIXTURE_ID environment variable is
 * deliberately ignored. The process-tree nodes need this: every node in one tree
 * inherits the same FIXTURE_ID, and if they honoured it they would all write to
 * the same oracle file and overwrite each other. A node reports as itself. */
ORC_UNUSED static void orc_begin_fixed(const char *id) {
    char path[512];
    orc_id = id;
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    snprintf(path, sizeof path, "%s.oracle", id);
    orc_file = fopen(path, "w");
    printf("FIXTURE_ID=%s%c", orc_id, 10);
    if (orc_file) {
        fprintf(orc_file, "FIXTURE_ID=%s%c", orc_id, 10);
        fflush(orc_file);
    }
}

/* One line, to the stream and to the file. */
ORC_UNUSED static void orc_emit(FILE *stream, const char *key, const char *fmt, va_list ap) {
    va_list ap2;
    va_copy(ap2, ap);
    fprintf(stream, "%s=", key);
    vfprintf(stream, fmt, ap);
    fputc('\n', stream);
    fflush(stream);
    if (orc_file) {
        fprintf(orc_file, "%s=", key);
        vfprintf(orc_file, fmt, ap2);
        fputc('\n', orc_file);
        fflush(orc_file);
    }
    va_end(ap2);
}

ORC_UNUSED static void orc_kv(const char *key, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); orc_emit(stdout, key, fmt, ap); va_end(ap);
}

ORC_UNUSED static void orc_obs(const char *key, const char *fmt, ...) {
    char k[128];
    va_list ap;
    snprintf(k, sizeof k, "OBS_%s", key);
    va_start(ap, fmt); orc_emit(stdout, k, fmt, ap); va_end(ap);
}

ORC_UNUSED static void orc_ekv(const char *key, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); orc_emit(stderr, key, fmt, ap); va_end(ap);
}

ORC_UNUSED static int orc_check(const char *key, int ok) {
    orc_kv(key, "%s", ok ? "yes" : "no");
    if (!ok) orc_failures++;
    return ok;
}

ORC_UNUSED static void orc_expect_death(const char *how) {
    orc_kv("EXPECT_DEATH", "%s", how);
}

ORC_UNUSED static unsigned long long orc_fnv1a(const unsigned char *p, size_t n) {
    unsigned long long h = 14695981039346656037ULL;
    size_t i;
    for (i = 0; i < n; i++) { h ^= (unsigned long long)p[i]; h *= 1099511628211ULL; }
    return h;
}

ORC_UNUSED static void orc_hex(const char *key, const unsigned char *p, size_t n) {
    char buf[1024];
    size_t i, o = 0;
    for (i = 0; i < n && o + 3 < sizeof buf; i++) {
        static const char *d = "0123456789abcdef";
        buf[o++] = d[(p[i] >> 4) & 0xf];
        buf[o++] = d[p[i] & 0xf];
    }
    buf[o] = 0;
    orc_kv(key, "%s", buf);
}

ORC_UNUSED static int orc_end(void) {
    orc_kv("RESULT", "%s", orc_failures == 0 ? "PASS" : "FAIL");
    if (orc_file) { fclose(orc_file); orc_file = NULL; }
    return 0;
}

#ifdef _WIN32
/* Win32 error names, hand-tabled so the emitted text does not depend on the
 * message table or the locale of whatever is emulating Windows. */
ORC_UNUSED static const char *orc_werr_name(unsigned long e) {
    switch (e) {
    case 0:    return "ERROR_SUCCESS";
    case 2:    return "ERROR_FILE_NOT_FOUND";
    case 3:    return "ERROR_PATH_NOT_FOUND";
    case 5:    return "ERROR_ACCESS_DENIED";
    case 6:    return "ERROR_INVALID_HANDLE";
    case 8:    return "ERROR_NOT_ENOUGH_MEMORY";
    case 18:   return "ERROR_NO_MORE_FILES";
    case 32:   return "ERROR_SHARING_VIOLATION";
    case 38:   return "ERROR_HANDLE_EOF";
    case 80:   return "ERROR_FILE_EXISTS";
    case 87:   return "ERROR_INVALID_PARAMETER";
    case 109:  return "ERROR_BROKEN_PIPE";
    case 122:  return "ERROR_INSUFFICIENT_BUFFER";
    case 126:  return "ERROR_MOD_NOT_FOUND";
    case 127:  return "ERROR_PROC_NOT_FOUND";
    case 145:  return "ERROR_DIR_NOT_EMPTY";
    case 183:  return "ERROR_ALREADY_EXISTS";
    case 193:  return "ERROR_BAD_EXE_FORMAT";
    case 203:  return "ERROR_ENVVAR_NOT_FOUND";
    case 206:  return "ERROR_FILENAME_EXCED_RANGE";
    case 232:  return "ERROR_NO_DATA";
    case 234:  return "ERROR_MORE_DATA";
    case 259:  return "ERROR_NO_MORE_ITEMS";
    case 298:  return "ERROR_TOO_MANY_POSTS";
    case 536:  return "ERROR_PIPE_LISTENING";
    case 997:  return "ERROR_IO_PENDING";
    case 998:  return "ERROR_NOACCESS";
    case 1157: return "ERROR_DLL_NOT_FOUND";
    case 1400: return "ERROR_INVALID_WINDOW_HANDLE";
    case 1411: return "ERROR_CLASS_DOES_NOT_EXIST";
    case 10013: return "WSAEACCES";
    case 10014: return "WSAEFAULT";
    case 10022: return "WSAEINVAL";
    case 10035: return "WSAEWOULDBLOCK";
    case 10038: return "WSAENOTSOCK";
    case 10047: return "WSAEAFNOSUPPORT";
    case 10048: return "WSAEADDRINUSE";
    case 10049: return "WSAEADDRNOTAVAIL";
    case 10050: return "WSAENETDOWN";
    case 10051: return "WSAENETUNREACH";
    case 10054: return "WSAECONNRESET";
    case 10057: return "WSAENOTCONN";
    case 10060: return "WSAETIMEDOUT";
    case 10061: return "WSAECONNREFUSED";
    case 10093: return "WSANOTINITIALISED";
    default:   return "ERROR_OTHER";
    }
}

/* Report GetLastError symbolically AND numerically: the name is the
 * deterministic part, the number is kept for anything the table misses. */
ORC_UNUSED static void orc_werr(const char *key, unsigned long e) {
    char k[128];
    orc_kv(key, "%s", orc_werr_name(e));
    if (strcmp(orc_werr_name(e), "ERROR_OTHER") == 0) {
        snprintf(k, sizeof k, "%s_CODE", key);
        orc_kv(k, "%lu", e);
    }
}

ORC_UNUSED static void orc_werr_now(const char *key) { orc_werr(key, GetLastError()); }

/* A UTF-16 string reported as the hex of its UTF-8 encoding: exact, printable,
 * and independent of whatever code page the console happens to be in. */
ORC_UNUSED static void orc_wide(const char *key_prefix, const wchar_t *w) {
    char utf8[1024];
    char klen[160], khex[160];
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, utf8, (int)sizeof utf8, NULL, NULL);
    size_t bytes = (n > 0) ? (size_t)(n - 1) : 0;   /* n includes the NUL */
    snprintf(klen, sizeof klen, "%s_LEN", key_prefix);
    snprintf(khex, sizeof khex, "%s_HEX", key_prefix);
    orc_kv(klen, "%lu", (unsigned long)bytes);
    if (bytes <= 64) orc_hex(khex, (const unsigned char *)utf8, bytes);
    else orc_kv(khex, "(elided,%lu bytes)", (unsigned long)bytes);
}

/* Like orc_wide, but as an OBSERVATION: for a wide string whose value depends on
 * the environment (a working directory, a module path). Emitting one of those
 * under a deterministic key makes a specimen look nondeterministic when it is
 * not, which is how this function came to exist. */
ORC_UNUSED static void orc_wide_obs(const char *key_prefix, const wchar_t *w) {
    char utf8[1024];
    char klen[160], khex[160];
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, utf8, (int)sizeof utf8, NULL, NULL);
    size_t bytes = (n > 0) ? (size_t)(n - 1) : 0;
    snprintf(klen, sizeof klen, "%s_LEN", key_prefix);
    snprintf(khex, sizeof khex, "%s_HEX", key_prefix);
    orc_obs(klen, "%lu", (unsigned long)bytes);
    if (bytes <= 64) {
        char hex[160];
        size_t i, o = 0;
        for (i = 0; i < bytes && o + 3 < sizeof hex; i++) {
            static const char *dig = "0123456789abcdef";
            hex[o++] = dig[((unsigned char)utf8[i] >> 4) & 0xf];
            hex[o++] = dig[(unsigned char)utf8[i] & 0xf];
        }
        hex[o] = 0;
        orc_obs(khex, "%s", hex);
    } else {
        orc_obs(khex, "(elided,%lu bytes)", (unsigned long)bytes);
    }
}

#endif /* _WIN32 */

#endif /* LEXE_ORACLE_WIN_H */
