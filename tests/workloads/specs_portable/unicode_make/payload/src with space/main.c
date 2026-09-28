/* The same question as unicode_cmd asks, restricted to what make can actually
 * do: the DIRECTORY has a space in it and so does the product, but no
 * prerequisite of any rule does.
 *
 * That restriction is the finding. See the Makefile beside this file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    printf("FIXTURE_ID=%s\n", id ? id : "portable-unicode-make");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("SOURCE_DIR_HAS_SPACE=yes\n");
    printf("PRODUCT_NAME_HAS_SPACE=yes\n");
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("RESULT=%s\n", (argc >= 1 && argv[0] && argv[0][0]) ? "PASS" : "FAIL");
    return 0;
}
