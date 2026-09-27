/* The ordinary case: one translation unit, one Makefile, one product.
 *
 * A portable specimen ships THIS, not a binary. Everything it prints is either
 * a deterministic fact about the source (so a consumer can compare it) or an
 * OBS_ fact about the machine that compiled it (so a consumer can see that a
 * compile really happened, and where).
 *
 * Deliberately self-contained: no shared oracle header, because a portable
 * package that reaches outside its own payload for a header is not a portable
 * package. The oracle is a line format, not a library.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *isa(void) {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#elif defined(__riscv) && __riscv_xlen == 64
    return "riscv64";
#elif defined(__i386__)
    return "i386";
#else
    return "unknown";
#endif
}

/* A pure-integer checksum, so the value is identical under every compiler and
 * optimisation level. If it ever differs, the source has undefined behaviour or
 * the toolchain is wrong -- either way it is not a portability question. */
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
    int i;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-c-single");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("TRANSLATION_UNITS=1\n");
    printf("CHECKSUM=%lu\n", checksum());
    printf("BUILD_ISA=%s\n", isa());
    printf("ARGC=%d\n", argc);
    for (i = 1; i < argc; i++) printf("ARGV_%d=%s\n", i, argv[i]);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
#if defined(__clang__)
    printf("OBS_BUILT_BY=clang %d.%d.%d\n", __clang_major__, __clang_minor__,
           __clang_patchlevel__);
#elif defined(__GNUC__)
    printf("OBS_BUILT_BY=gcc %d.%d.%d\n", __GNUC__, __GNUC_MINOR__,
           __GNUC_PATCHLEVEL__);
#else
    printf("OBS_BUILT_BY=unknown\n");
#endif
    /* The specimen asserts only what it can know by itself. The VALUE of the
     * checksum is not predictable by hand, so it is printed deterministically
     * and the corpus index records it; what the specimen checks is that it is
     * stable, that the compiler identified an ISA, and that it was launched
     * with an argv at all. */
    printf("CHECKSUM_STABLE=%s\n", checksum() == checksum() ? "yes" : "no");
    printf("ISA_KNOWN=%s\n", strcmp(isa(), "unknown") == 0 ? "no" : "yes");
    printf("ARGV0_PRESENT=%s\n", (argc >= 1 && argv[0] && argv[0][0]) ? "yes" : "no");
    printf("RESULT=%s\n",
           (checksum() == checksum() && strcmp(isa(), "unknown") != 0
            && argc >= 1 && argv[0] && argv[0][0]) ? "PASS" : "FAIL");
    return 0;
}
