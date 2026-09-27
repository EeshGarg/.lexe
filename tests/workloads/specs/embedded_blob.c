/* Self-contained: every byte it needs is inside the image. No data files, no
 * configuration, no network. Verifies an embedded 1 MiB blob it generates from
 * a seed held in .rodata. */
#include "oracle.h"
#include <unistd.h>

static const unsigned long SEED = 0x2545F4914F6CDD1DUL;
#define BLOB_N (1024u * 1024u)

int main(void) {
    static unsigned char blob[BLOB_N];
    unsigned long x = SEED;
    unsigned int i;
    orc_begin("linux-format-selfcontained");
    for (i = 0; i < BLOB_N; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        blob[i] = (unsigned char)(x & 0xff);
    }
    orc_kv("BLOB_BYTES", "%u", BLOB_N);
    orc_kv("BLOB_HASH", "%016lx", orc_fnv1a(blob, BLOB_N));
    orc_check("NO_EXTERNAL_FILES", 1);
    return orc_end();
}
