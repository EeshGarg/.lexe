/* Built by one compiler invocation and nothing else.
 *
 * `build.system: "command"` with argv ["cc", "-O2", ...] is the smallest
 * possible portable build: no make, no cmake, no shell, no script in the
 * payload. It is also the only shape in which the compiler's argv is IN THE
 * SIGNED MANIFEST rather than in a file the manifest merely points at.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    unsigned long h = 2166136261UL;
    int i;
    for (i = 0; i < 2048; i++) { h ^= (unsigned long)(i & 0xff); h *= 16777619UL; h &= 0xffffffffUL; }
    printf("FIXTURE_ID=%s\n", id ? id : "portable-bare-cc");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("BUILD_SYSTEM=command\n");
    printf("BUILD_DRIVER=none\n");
    printf("CHECKSUM=%lu\n", h);
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("RESULT=%s\n", (argc >= 1 && argv[0] && argv[0][0]) ? "PASS" : "FAIL");
    return 0;
}
