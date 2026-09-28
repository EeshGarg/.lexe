/* One program, six ways of linking it.
 *
 * The program says almost nothing about its own linkage on purpose. Whether it
 * is PIE, whether it has a program interpreter, whether DT_NEEDED is empty and
 * whether .symtab survived are all read out of the built FILE with readelf by
 * the generator, which is a witness outside the program; a program that reported
 * its own e_type would be reporting a compile-time guess.
 *
 * What it does prove is that the differently-linked product still runs and still
 * computes the same answer, which is the other half of the property.
 */
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

static unsigned long checksum(void) {
    unsigned long h = 2166136261UL;
    int i;
    for (i = 0; i < 4096; i++) {
        h ^= (unsigned long)(i & 0xff);
        h *= 16777619UL;
        h &= 0xffffffffUL;
    }
    return h;
}

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    printf("FIXTURE_ID=%s\n", id ? id : "portable-link");
    printf("PAYLOAD_KIND=portable-source\n");
    /* __PIC__/__PIE__ are what the COMPILER was told, which is not the same
     * claim as what the linker produced -- so they are observations, and the
     * file's real e_type is the declaration. */
#if defined(__PIE__)
    printf("OBS_COMPILED_PIE_LEVEL=%d\n", (int)__PIE__);
#else
    printf("OBS_COMPILED_PIE_LEVEL=none\n");
#endif
    printf("CHECKSUM=%lu\n", checksum());
    printf("BUILD_ISA=%s\n", isa());
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("CHECKSUM_STABLE=%s\n", checksum() == checksum() ? "yes" : "no");
    printf("ISA_KNOWN=%s\n", strcmp(isa(), "unknown") == 0 ? "no" : "yes");
    printf("RESULT=%s\n",
           (checksum() == checksum() && strcmp(isa(), "unknown") != 0
            && argc >= 1 && argv[0] && argv[0][0]) ? "PASS" : "FAIL");
    return 0;
}
