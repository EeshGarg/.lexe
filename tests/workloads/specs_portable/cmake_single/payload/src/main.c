/* The same ordinary program, built by cmake instead of make.
 *
 * `build.system: "cmake"` is a second driver the runtime invokes itself, and it
 * behaves differently from make in ways a corpus should cover: it wants its own
 * build directory, it decides the compiler by probing rather than by $(CC), and
 * it writes a cache that survives between invocations. The product has to land
 * at the path the manifest declares regardless, which is what
 * CMAKE_RUNTIME_OUTPUT_DIRECTORY below is for.
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

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    unsigned long h = 2166136261UL;
    int i, failures = 0;
    for (i = 0; i < 2048; i++) { h ^= (unsigned long)(i & 0xff); h *= 16777619UL; h &= 0xffffffffUL; }
    printf("FIXTURE_ID=%s\n", id ? id : "portable-cmake");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("BUILD_SYSTEM=cmake\n");
#ifdef PORTABLE_VIA_CMAKE
    printf("CMAKE_DEFINE_REACHED_COMPILER=yes\n");
#else
    printf("CMAKE_DEFINE_REACHED_COMPILER=no\n");
    failures++;
#endif
    printf("CHECKSUM=%lu\n", h);
    printf("BUILD_ISA=%s\n", isa());
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (strcmp(isa(), "unknown") == 0) failures++;
    printf("ISA_KNOWN=%s\n", strcmp(isa(), "unknown") ? "yes" : "no");
    printf("ARGV0_PRESENT=%s\n", (argc >= 1 && argv[0] && argv[0][0]) ? "yes" : "no");
    printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
    return 0;
}
