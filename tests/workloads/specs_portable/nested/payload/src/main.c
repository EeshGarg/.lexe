/* The interesting thing about this package is its SHAPE, not its program: the
 * sources are three directories below sourceDir, the include path has to reach
 * them, and an archive or an installer that flattened the tree would break it
 * without producing a diagnostic anybody could act on. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "module/deep/leaf.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    int failures = 0;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-nested-layout");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("SOURCE_DEPTH=%d\n", leaf_depth());
    printf("LEAF_PATH=%s\n", leaf_path());
    printf("OBS_COMPILER_FILE=%s\n", __FILE__);
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (leaf_depth() != 3) failures++;
    if (strcmp(leaf_path(), "src/module/deep/leaf.c") != 0) failures++;
    printf("NESTED_UNIT_LINKED=%s\n", failures == 0 ? "yes" : "no");
    printf("RESULT=%s\n", (failures == 0 && argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
