/* Built by `build.system: "command"` -- the escape hatch driver, where the
 * package carries its own argv instead of relying on make or cmake.
 *
 * It is the driver a real recipe reaches for when its build is a script: an
 * autotools configure, a vendored bootstrap, a compiler wrapper. The manifest
 * names the argv, so what runs is visible before anything runs; the script is
 * shipped in the payload like any other source file.
 *
 * The program reports the marker the script passed through the compiler, so
 * "the declared argv is what built this" is observable and not assumed.
 */
#include <stdio.h>
#include <stdlib.h>

#ifndef BUILT_BY_MARKER
#define BUILT_BY_MARKER "unset"
#endif

int main(void) {
    const char *id = getenv("FIXTURE_ID");
    printf("FIXTURE_ID=%s\n", id ? id : "portable-command-driver");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("BUILD_SYSTEM=command\n");
    printf("BUILT_BY_MARKER=%s\n", BUILT_BY_MARKER);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("MARKER_SET=%s\n",
           BUILT_BY_MARKER[0] == 'b' ? "yes" : "no");
    printf("RESULT=%s\n", BUILT_BY_MARKER[0] == 'b' ? "PASS" : "FAIL");
    return 0;
}
