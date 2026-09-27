/* The program a slow build produces. It is small; the build is the specimen.
 *
 * It reports GEN_UNITS, which comes from the header the build generated, so the
 * value proves the generation step ran and how much of it ran -- a build that
 * was interrupted and resumed with a stale generated.h reports the wrong number
 * here rather than silently producing a smaller program.
 */
#include <stdio.h>
#include <stdlib.h>
#include "generated.h"

int main(void) {
    const char *id = getenv("FIXTURE_ID");
    unsigned long a = gen_all(2166136261UL);
    printf("FIXTURE_ID=%s\n", id ? id : "portable-slow-build");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("GENERATED_UNITS=%d\n", GEN_UNITS);
    printf("GEN_ALL=%lu\n", a);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("GEN_ALL_STABLE=%s\n", gen_all(2166136261UL) == a ? "yes" : "no");
    printf("RESULT=%s\n", (gen_all(2166136261UL) == a && GEN_UNITS > 0) ? "PASS" : "FAIL");
    return 0;
}
