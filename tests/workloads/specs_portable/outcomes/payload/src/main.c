/* The ordinary program the outcome variants build, fail to build, build into the
 * wrong place, build and then break the permissions of, or wrap in a script.
 * Nothing here is unusual; the variation is entirely in the Makefile. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *isa(void) {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#else
    return "unknown";
#endif
}

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    unsigned long h = 2166136261UL;
    int i;
    for (i = 0; i < 2048; i++) { h ^= (unsigned long)(i & 0xff); h *= 16777619UL; h &= 0xffffffffUL; }
    printf("FIXTURE_ID=%s\n", id ? id : "portable-outcome");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("CHECKSUM=%lu\n", h);
    printf("BUILD_ISA=%s\n", isa());
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("ISA_KNOWN=%s\n", strcmp(isa(), "unknown") == 0 ? "no" : "yes");
    printf("RESULT=%s\n",
           (strcmp(isa(), "unknown") != 0 && argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
