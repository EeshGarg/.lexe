#include "core.h"

unsigned long core_mix(unsigned long seed, int rounds) {
    unsigned long h = seed;
    int i;
    for (i = 0; i < rounds; i++) {
        h ^= (unsigned long)(i & 0xffff);
        h *= 16777619UL;
        h &= 0xffffffffUL;
    }
    return h;
}

const char *core_id(void) { return "core-1"; }
