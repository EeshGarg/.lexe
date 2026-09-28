/* Consumes libutil.a, which the same build produced one step earlier. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    int failures = 0;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-static-lib");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("LINK_KIND=static-archive\n");
    printf("UTIL_VALUE=%d\n", util_value());
    printf("UTIL_BUILD_ID=%s\n", util_build_id());
    printf("UTIL_MIX=%lu\n", util_mix(2166136261UL, 512));
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (util_value() != 4242) failures++;
    if (strcmp(util_build_id(), "libutil-static-1") != 0) failures++;
    printf("ARCHIVE_LINKED=%s\n", failures == 0 ? "yes" : "no");
    printf("RESULT=%s\n", (failures == 0 && argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
