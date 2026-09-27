/* Portable C, built BOTH as a PE and as a native ELF from this one source, so a
 * consumer has a native reference cell to compare the translated runs against.
 * argv[1] selects which streams are used: out, err, or both. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "both";
    int i;
    orc_begin("pe-io-streams");
    orc_kv("STREAM_MODE", "%s", mode);
    for (i = 1; i <= 8; i++) {
        if (strcmp(mode, "err") != 0) orc_kv("OUT_LINE", "%d", i);
        if (strcmp(mode, "out") != 0) orc_ekv("ERR_LINE", "%d", i);
    }
    orc_kv("OUT_TOTAL", "%s", strcmp(mode, "err") == 0 ? "0" : "8");
    orc_kv("ERR_TOTAL", "%s", strcmp(mode, "out") == 0 ? "0" : "8");
    return orc_end();
}
