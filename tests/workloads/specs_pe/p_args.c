/* Reports every argument as the runtime handed it over (the ANSI/narrow argv
 * the C runtime builds), by byte length and hex. The wide-character view of the
 * same command line is w_argsw.c: on Windows those two can disagree, and a
 * corpus that only looked at one would not notice. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    int i;
    unsigned long long h = 14695981039346656037ULL;
    orc_begin("pe-arg-narrow");
    orc_kv("ARGC", "%d", argc);
    orc_obs("ARGV0_RAW", "%s", argc > 0 ? argv[0] : "(none)");
    for (i = 1; i < argc; i++) {
        char k[64];
        size_t n = strlen(argv[i]);
        snprintf(k, sizeof k, "ARG_%d_LEN", i);
        orc_kv(k, "%lu", (unsigned long)n);
        snprintf(k, sizeof k, "ARG_%d_HEX", i);
        if (n <= 64) orc_hex(k, (const unsigned char *)argv[i], n);
        else orc_kv(k, "(elided,%lu bytes)", (unsigned long)n);
        h ^= orc_fnv1a((const unsigned char *)argv[i], n);
        h *= 1099511628211ULL;
    }
    orc_kv("ARGS_HASH", "%016llx", h);
    orc_check("ARGV_NULL_TERMINATED", argv[argc] == NULL);
    return orc_end();
}
