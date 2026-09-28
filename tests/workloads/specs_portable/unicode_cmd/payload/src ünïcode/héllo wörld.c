/* A source file whose NAME contains a space and four non-ASCII characters, in a
 * directory whose name does too, producing a product whose name does too.
 *
 * None of that is exotic: it is what happens the first time a package is written
 * by somebody whose language is not English, or is unpacked under a directory
 * called "My Documents". What it breaks is everything that builds a command line
 * by concatenating strings -- which is why this recipe's build is a script that
 * quotes every path, and why the manifest's entrypoint is a path with a space in
 * it that the relative-payload-path rules happen to permit.
 *
 * The source file itself is pure ASCII inside. The non-ASCII is in the file
 * NAMES, because that is where it causes trouble.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shared ütil.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    int failures = 0;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-unicode-command");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("PATHS_CONTAIN_SPACES=yes\n");
    printf("PATHS_CONTAIN_NON_ASCII=yes\n");
    printf("UTIL_ANSWER=%d\n", util_answer());
    printf("UTIL_ID=%s\n", util_id());
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (util_answer() != 8888) failures++;
    if (strcmp(util_id(), "unicode-util-1") != 0) failures++;
    printf("BOTH_UNITS_LINKED=%s\n", failures == 0 ? "yes" : "no");
    printf("RESULT=%s\n", (failures == 0 && argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
