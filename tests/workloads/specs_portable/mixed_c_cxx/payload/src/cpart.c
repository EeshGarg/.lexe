/* Compiled by the C compiler. */
#include "cpart.h"

int cpart_value(void) { return 1701; }

const char *cpart_language(void) {
#ifdef __cplusplus
    return "c++";                       /* never taken: this file is built as C */
#else
    return "c";
#endif
}

unsigned long cpart_mix(unsigned long seed, int rounds) {
    unsigned long h = seed;
    int i;
    for (i = 0; i < rounds; i++) {
        h ^= (unsigned long)(i & 0xffff);
        h *= 16777619UL;
        h &= 0xffffffffUL;
    }
    return h;
}
