/* Links against the shared library the same recipe just built.
 *
 * The program cannot see its own RUNPATH and does not try to: that is read out
 * of the built file with readelf, by the generator, which is a better witness
 * than the program's own opinion. What the program CAN prove is that the
 * library was found and is the right one -- if the loader failed, this program
 * never starts at all and prints nothing, which is itself the observation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libutil.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    int failures = 0;
    unsigned long m = util_mix(2166136261UL, 512);
    printf("FIXTURE_ID=%s\n", id ? id : "portable-shared-lib");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("UTIL_VALUE=%d\n", util_value());
    printf("UTIL_BUILD_ID=%s\n", util_build_id());
    printf("UTIL_MIX=%lu\n", m);
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (util_value() != 4242) failures++;
    if (strcmp(util_build_id(), "libutil-1") != 0) failures++;
    printf("SHARED_LIB_RESOLVED=%s\n", failures == 0 ? "yes" : "no");
    printf("ARGV0_PRESENT=%s\n", (argc >= 1 && argv[0] && argv[0][0]) ? "yes" : "no");
    printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
    return 0;
}
