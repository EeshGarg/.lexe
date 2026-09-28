/* Links against a shared library cmake built in the same run. The RUNPATH is set
 * by cmake properties rather than by a -Wl,-rpath the recipe wrote, which is a
 * different way to get to the same DT_RUNPATH string -- and a different set of
 * ways to get it wrong. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libshared.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    int failures = 0;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-cmake-shared");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("BUILD_SYSTEM=cmake\n");
    printf("SHARED_VALUE=%d\n", shared_value());
    printf("SHARED_ID=%s\n", shared_id());
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (shared_value() != 5150) failures++;
    if (strcmp(shared_id(), "cmake-shared-1") != 0) failures++;
    printf("SHARED_LIB_RESOLVED=%s\n", failures == 0 ? "yes" : "no");
    printf("RESULT=%s\n", (failures == 0 && argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
