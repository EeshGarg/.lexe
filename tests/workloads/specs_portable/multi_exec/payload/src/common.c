#include <stdio.h>
#include <stdlib.h>
#include "common.h"

unsigned long mix(unsigned long seed, int rounds) {
    unsigned long h = seed;
    int i;
    for (i = 0; i < rounds; i++) {
        h ^= (unsigned long)(i & 0xffff);
        h *= 16777619UL;
        h &= 0xffffffffUL;
    }
    return h;
}

void emit_common(const char *program, const char *fallback_id) {
    const char *id = getenv("FIXTURE_ID");
    printf("FIXTURE_ID=%s\n", id ? id : fallback_id);
    printf("PAYLOAD_KIND=portable-source\n");
    printf("PROGRAM=%s\n", program);
    printf("PROGRAMS_IN_PACKAGE=3\n");
    printf("MIX=%lu\n", mix(2166136261UL, 256));
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
}
