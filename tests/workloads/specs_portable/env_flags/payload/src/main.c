/* Reports which build profile the RECIPE chose, and separately what the compiler
 * was actually given.
 *
 * PROFILE is a string the Makefile put in with -D, so it says what the recipe
 * decided. OPTIMIZED comes from __OPTIMIZE__, which only the compiler can set.
 * Printing both is the point: a recipe that says "debug" and still compiles at
 * -O2 is a recipe whose environment handling does not work, and one value alone
 * cannot show that.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PORTABLE_PROFILE
#define PORTABLE_PROFILE "unset"
#endif

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    printf("FIXTURE_ID=%s\n", id ? id : "portable-env-flags");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("PROFILE=%s\n", PORTABLE_PROFILE);
#if defined(__OPTIMIZE__)
    printf("OPTIMIZED=yes\n");
#else
    printf("OPTIMIZED=no\n");
#endif
#if defined(NDEBUG)
    printf("NDEBUG=yes\n");
#else
    printf("NDEBUG=no\n");
#endif
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("RESULT=%s\n", (argc >= 1 && argv[0] && argv[0][0]) ? "PASS" : "FAIL");
    return 0;
}
