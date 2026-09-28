/* The program is beside the point. What this specimen measures is which files
 * exist after an install: doc/README.txt must be there, and nothing from src --
 * not this file, not the build-only notes, and not the stamp the build itself
 * drops into the source directory while running. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    printf("FIXTURE_ID=%s\n", id ? id : "portable-hygiene");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("PURPOSE=install-hygiene\n");
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("RESULT=%s\n", (argc >= 1 && argv[0] && argv[0][0]) ? "PASS" : "FAIL");
    return 0;
}
