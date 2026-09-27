/* Consumes stdin to EOF and attests to what it read. Fed a fixed 4096-byte input
 * by the runner.
 *
 * argv[1] selects the mode, and the difference between the two is a real Windows
 * property that cost this corpus a wrong declaration to learn:
 *
 *   binary  set _O_BINARY on fd 0 first. Every one of the 4096 bytes arrives.
 *   text    leave the C runtime default. On Windows that is TEXT mode, where
 *           byte 0x1A (Ctrl-Z, the DOS end-of-file) TERMINATES the stream. The
 *           runner's input has its first 0x1A at offset 35, so a Windows program
 *           in text mode sees 35 bytes and a clean EOF, while the same source
 *           running natively on Linux sees all 4096.
 *
 * Neither is a bug. A program that ships to Windows and reads binary data on
 * stdin has to ask for binary mode, and one that does not will silently truncate. */
#include "oracle_win.h"

#ifdef _WIN32
#  include <fcntl.h>
#  include <io.h>
#endif

int main(int argc, char **argv) {
    unsigned char buf[4096];
    unsigned long long h = 14695981039346656037ULL;
    unsigned long total = 0;
    size_t n;
    const char *mode = argc > 1 ? argv[1] : "binary";
    orc_begin("pe-io-stdin");
    orc_kv("STDIN_MODE_REQUESTED", "%s", mode);
#ifdef _WIN32
    if (strcmp(mode, "binary") == 0) {
        orc_kv("SETMODE_BINARY", "%s", _setmode(_fileno(stdin), _O_BINARY) != -1 ? "ok" : "fail");
        orc_kv("PLATFORM_HAS_TEXT_MODE", "yes");
    } else {
        orc_kv("SETMODE_BINARY", "not-requested");
        orc_kv("PLATFORM_HAS_TEXT_MODE", "yes");
    }
#else
    orc_kv("SETMODE_BINARY", "not-applicable");
    orc_kv("PLATFORM_HAS_TEXT_MODE", "no");
#endif
    while ((n = fread(buf, 1, sizeof buf, stdin)) > 0) {
        size_t i;
        for (i = 0; i < n; i++) { h ^= (unsigned long long)buf[i]; h *= 1099511628211ULL; }
        total += (unsigned long)n;
    }
    orc_kv("STDIN_BYTES", "%lu", total);
    orc_kv("STDIN_HASH", "%016llx", h);
    orc_check("STDIN_NOT_EMPTY", total > 0);
    orc_check("AT_EOF", feof(stdin) != 0);
    return orc_end();
}
