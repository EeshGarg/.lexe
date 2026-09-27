/* Consumes stdin to EOF and attests to what it read. The fixture is fed a fixed
 * 4096-byte input by the runner, so the hash is deterministic. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    unsigned char buf[8192];
    unsigned long h = 14695981039346656037UL;
    size_t total = 0;
    ssize_t n;
    orc_begin("linux-io-stdin-consumed");
    while ((n = read(0, buf, sizeof buf)) > 0) {
        ssize_t i;
        for (i = 0; i < n; i++) { h ^= (unsigned long)buf[i]; h *= 1099511628211UL; }
        total += (size_t)n;
    }
    orc_kv("STDIN_BYTES", "%lu", (unsigned long)total);
    orc_kv("STDIN_HASH", "%016lx", h);
    orc_check("READ_TO_EOF", n == 0);
    orc_check("STDIN_NOT_EMPTY", total > 0);
    return orc_end();
}
