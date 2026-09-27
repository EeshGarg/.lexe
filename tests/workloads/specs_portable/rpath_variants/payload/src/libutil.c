/* The shared library the recipe builds and then links the program against.
 *
 * It exists so the portable build has to produce TWO artifacts with an ordering
 * between them, install both, and arrange for the program to find the library
 * at run time on a machine whose directory layout the publisher never saw. That
 * last part is where the interesting failures are, and it is why the rpath
 * variants of this recipe exist as separate specimens.
 */
#include "libutil.h"

int util_value(void) { return 4242; }

const char *util_build_id(void) { return "libutil-1"; }

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
