/* A program that compiles, links, runs and is correct, and about which the
 * compiler has three complaints.
 *
 * This is the most common state of real source: warnings are not errors, the
 * build exits 0, the product works, and anything that treats a non-empty build
 * stderr as failure rejects most of the software in the world. The declaration
 * for this specimen says the build SUCCEEDS and that its stderr contains
 * "warning:" -- both halves matter.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -Wunused-parameter: the parameter is never read. */
static int unused_parameter_here(int ignored) {
    return 1;
}

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    int unused_local = 7;            /* -Wunused-variable */
    unsigned u = 3;
    int s = 3;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-outcome-warns");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("WARNED_BUT_BUILT=yes\n");
    /* -Wsign-compare: signed/unsigned comparison. */
    printf("SIGN_COMPARE_EQUAL=%s\n", (u == s) ? "yes" : "no");
    printf("HELPER=%d\n", unused_parameter_here(0));
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("RESULT=%s\n", (argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
