/* Built by cmake. What the program reports about the build is a -D the list file
 * put there, so "cmake really did this" is observable rather than assumed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#ifndef CMAKE_SHAPE
#define CMAKE_SHAPE "unset"
#endif

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    unsigned long h = 2166136261UL;
    int i;
    for (i = 0; i < 2048; i++) { h ^= (unsigned long)(i & 0xff); h *= 16777619UL; h &= 0xffffffffUL; }
    printf("FIXTURE_ID=%s\n", id ? id : "portable-cmake-variant");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("BUILD_SYSTEM=cmake\n");
    printf("CMAKE_SHAPE=%s\n", CMAKE_SHAPE);
    printf("UTIL_VALUE=%d\n", util_value());
    printf("UTIL_ID=%s\n", util_id());
    printf("CHECKSUM=%lu\n", h);
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("RESULT=%s\n",
           (util_value() == 909 && strcmp(util_id(), "cmake-subdir-util-1") == 0
            && argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
