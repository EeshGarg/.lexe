/* Goes into libutil.a and then INTO the executable. Nothing of this file exists
 * as a separate artifact once the link is done, which is the difference from the
 * shared-library recipe next door: there is no run-time lookup to get wrong, so
 * there is nothing for relocation to break. */
#include "util.h"

int util_value(void) { return 4242; }

const char *util_build_id(void) { return "libutil-static-1"; }

unsigned long util_mix(unsigned long seed, int rounds) {
    unsigned long h = seed;
    int i;
    for (i = 0; i < rounds; i++) {
        h ^= (unsigned long)(i & 0xffff);
        h *= 16777619UL;
        h &= 0xffffffffUL;
    }
    return h;
}
