/* One program, six link lines.
 *
 * Every portable-rpath-* specimen builds THIS source against the same
 * libutil.so, differing only in the run-time library search path the Makefile
 * bakes into the product. The point of the family is the RUNPATH string each
 * ordinary-looking idiom actually produces -- read out of the built file with
 * readelf, and recorded per variant -- and then whether the product still
 * starts once the directory that built it is gone.
 *
 * The program says nothing about rpath. If the loader could not find the
 * library, this program is never entered and there is no output at all; if it
 * was found, the value below proves it was the right library. Those two
 * outcomes are the measurement.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libutil.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    int failures = 0;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-rpath");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("UTIL_VALUE=%d\n", util_value());
    printf("UTIL_BUILD_ID=%s\n", util_build_id());
    printf("UTIL_MIX=%lu\n", util_mix(2166136261UL, 512));
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (util_value() != 4242) failures++;
    if (strcmp(util_build_id(), "libutil-1") != 0) failures++;
    printf("SHARED_LIB_RESOLVED=%s\n", failures == 0 ? "yes" : "no");
    printf("ARGV0_PRESENT=%s\n", (argc >= 1 && argv[0] && argv[0][0]) ? "yes" : "no");
    printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
    return 0;
}
