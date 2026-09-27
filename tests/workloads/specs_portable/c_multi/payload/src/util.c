/* Translation unit 1 of 4: pure integer arithmetic, no I/O. */
#include "common.h"

unsigned long util_mix(unsigned long seed, int rounds) {
    unsigned long h = seed;
    int i;
    for (i = 0; i < rounds; i++) {
        h ^= (unsigned long)(i & 0xffff);
        h *= 16777619UL;
        h &= 0xffffffffUL;
        h ^= h >> 13;
    }
    return h & 0xffffffffUL;
}

const char *util_isa(void) {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#elif defined(__riscv) && __riscv_xlen == 64
    return "riscv64";
#else
    return "unknown";
#endif
}
