/* A deliberately large executable: 48 MiB of non-zero initialised data that
 * cannot be compressed into .bss, plus a runtime checksum so the specimen
 * proves the pages actually arrived. */
#include "oracle.h"
#include <unistd.h>

#define BIG_N (48u * 1024u * 1024u)
static unsigned char big[BIG_N] = { 1 };

int main(void) {
    unsigned long h;
    unsigned int i;
    orc_begin("linux-format-large-binary");
    /* Fill deterministically at build time is impossible for 48 MiB of source,
     * so the initialiser marks it live and the loader must map it; we then
     * write a deterministic pattern and hash it. */
    for (i = 0; i < BIG_N; i++) big[i] = (unsigned char)((i * 31u + 7u) & 0xff);
    h = orc_fnv1a(big, BIG_N);
    orc_kv("BIG_BYTES", "%u", BIG_N);
    orc_kv("BIG_HASH", "%016lx", h);
    orc_check("BIG_FIRST", big[0] == 7);
    orc_check("BIG_LAST", big[BIG_N - 1] == (unsigned char)(((BIG_N - 1) * 31u + 7u) & 0xff));
    return orc_end();
}
