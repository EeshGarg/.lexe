/* One source, five language standards.
 *
 * This file is strict C89: no // comments, no declaration after a statement, no
 * long long, no mixed declarations. It therefore compiles unchanged under
 * -std=c89, c99, c11, c17 and gnu89 with -pedantic-errors, which is the point --
 * the five specimens differ only in the -std the Makefile passes, and what the
 * program reports is what the COMPILER says it was given, not what the recipe
 * claims.
 *
 * __STDC_VERSION__ is deliberately reported as "undefined" where the compiler
 * does not define it. C89 has no __STDC_VERSION__ at all, and a specimen that
 * printed 0 there would be inventing a value.
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
    printf("FIXTURE_ID=%s\n", id ? id : "portable-std-c");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("LANGUAGE=c\n");
#if defined(__STDC_VERSION__)
    printf("STDC_VERSION=%ld\n", (long)__STDC_VERSION__);
#else
    printf("STDC_VERSION=undefined\n");
#endif
#if defined(__STRICT_ANSI__)
    printf("STRICT_ANSI=yes\n");
#else
    printf("STRICT_ANSI=no\n");
#endif
#if defined(__STDC_HOSTED__)
    printf("STDC_HOSTED=%d\n", (int)__STDC_HOSTED__);
#else
    printf("STDC_HOSTED=undefined\n");
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
