/* Reports every argument byte-exactly and unambiguously: length plus lowercase
 * hex, so empty strings, embedded spaces, trailing whitespace and multi-byte
 * UTF-8 are all distinguishable. One binary serves every argument fixture; the
 * fixtures differ only in what the runner passes. */
#include "oracle.h"
#include <unistd.h>

static void hexout(const char *s) {
    size_t i, n = strlen(s);
    for (i = 0; i < n; i++) printf("%02x", (unsigned char)s[i]);
}

int main(int argc, char **argv) {
    int i;
    unsigned long h = 14695981039346656037UL;
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-arg-report");
    orc_kv("ARGC", "%d", argc);
    orc_obs("ARGV0_RAW", "%s", argc > 0 ? argv[0] : "(none)");
    for (i = 1; i < argc; i++) {
        printf("ARG_%d_LEN=%lu\n", i, (unsigned long)strlen(argv[i]));
        if (strlen(argv[i]) <= 64) {
            printf("ARG_%d_HEX=", i);
            hexout(argv[i]);
            putchar('\n');
        } else {
            printf("ARG_%d_HEX=(elided,%lu bytes)\n", i, (unsigned long)strlen(argv[i]));
        }
        h ^= orc_fnv1a((const unsigned char *)argv[i], strlen(argv[i]));
        h *= 1099511628211UL;
    }
    orc_kv("ARGS_HASH", "%016lx", h);
    orc_check("ARGV_NULL_TERMINATED", argv[argc] == NULL);
    return orc_end();
}
