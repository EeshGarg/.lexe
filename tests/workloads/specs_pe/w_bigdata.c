/* A deliberately large PE: 48 MiB of initialised data that cannot be folded into
 * .bss, checksummed at runtime so the pages must really arrive. */
#include "oracle_win.h"

#define BIG_N (48u * 1024u * 1024u)
static unsigned char big[BIG_N] = { 1 };

int main(void) {
    unsigned i;
    orc_begin("pe-format-large-binary");
    for (i = 0; i < BIG_N; i++) big[i] = (unsigned char)((i * 31u + 7u) & 0xff);
    orc_kv("BIG_BYTES", "%u", BIG_N);
    orc_kv("BIG_HASH", "%016llx", orc_fnv1a(big, BIG_N));
    orc_check("BIG_FIRST", big[0] == 7);
    orc_check("BIG_LAST", big[BIG_N - 1] == (unsigned char)(((BIG_N - 1) * 31u + 7u) & 0xff));
    return orc_end();
}
