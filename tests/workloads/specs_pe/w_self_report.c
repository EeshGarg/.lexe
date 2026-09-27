/* The PE control case: it runs, it reports, it exits 0. Format properties
 * (subsystem, machine, stripped) are build properties verified from the PE
 * headers by the generator, not claimed here. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    static const unsigned char pattern[16] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    (void)argv;
    orc_begin("pe-format-console");
    orc_kv("ARGC", "%d", argc);
    orc_kv("PATTERN_HASH", "%016llx", orc_fnv1a(pattern, sizeof pattern));
    orc_kv("DOUBLE_MATH", "%.6f", 1.0 / 3.0 * 3.0);
    orc_kv("POINTER_BITS", "%d", (int)(sizeof(void *) * 8));
    orc_check("ARGV0_PRESENT", argc > 0 && argv[0] != NULL);
    return orc_end();
}
