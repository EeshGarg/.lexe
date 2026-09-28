/* 8 MiB of deterministic bytes on stdout, with the length and FNV-1a hash of
 * that stream reported on stderr. The runner recomputes the hash over what it
 * captured, so the claim is checkable without embedding 8 MiB in the manifest. */
#include "oracle.h"
#include <unistd.h>

#define BULK (8u * 1024u * 1024u)

int main(void) {
    static unsigned char buf[65536];
    unsigned long h = 14695981039346656037UL;
    unsigned long written = 0;
    unsigned long x = 0x9E3779B97F4A7C15UL;
    orc_ebegin("linux-io-bulk-stdout");
    while (written < BULK) {
        size_t i, chunk = sizeof buf;
        if (BULK - written < chunk) chunk = BULK - written;
        for (i = 0; i < chunk; i++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            buf[i] = (unsigned char)(x & 0xff);
            h ^= (unsigned long)buf[i]; h *= 1099511628211UL;
        }
        if (fwrite(buf, 1, chunk, stdout) != chunk) {
            fprintf(stderr, "WRITE_FAILED=yes\nRESULT=FAIL\n");
            return 1;
        }
        written += (unsigned long)chunk;
    }
    fflush(stdout);
    fprintf(stderr, "BULK_BYTES=%lu\n", written);
    fprintf(stderr, "BULK_FNV1A=%016lx\n", h);
    fprintf(stderr, "RESULT=PASS\n");
    return 0;
}
