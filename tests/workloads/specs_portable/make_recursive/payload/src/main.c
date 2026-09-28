/* The top of a recursive build: two sub-makes produced the objects this links. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core.h"
#include "util.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    int failures = 0;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-make-recursive");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("BUILD_SHAPE=recursive-make\n");
    printf("SUBDIRS=2\n");
    printf("CORE_ID=%s\n", core_id());
    printf("UTIL_ID=%s\n", util_id());
    printf("CORE_MIX=%lu\n", core_mix(2166136261UL, 256));
    printf("UTIL_ANSWER=%d\n", util_answer());
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (strcmp(core_id(), "core-1") != 0) failures++;
    if (strcmp(util_id(), "util-1") != 0) failures++;
    if (util_answer() != 31337) failures++;
    printf("BOTH_SUBDIRS_LINKED=%s\n", failures == 0 ? "yes" : "no");
    printf("RESULT=%s\n", (failures == 0 && argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
