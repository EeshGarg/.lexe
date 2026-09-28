/* Includes a header that is not in the package. config.h is produced by
 * configure.sh during the build, from real compile probes of the host. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    int failures = 0;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-configure-step");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("BUILD_SHAPE=configure-then-compile\n");
    printf("CONFIG_STAMP=%s\n", CONFIG_STAMP);
    printf("CONFIG_HAVE_STDINT=%d\n", CONFIG_HAVE_STDINT);
    printf("CONFIG_HAVE_UNISTD=%d\n", CONFIG_HAVE_UNISTD);
    /* The probe for a header that cannot exist is the control: a configure step
     * that answered "yes" to everything would look identical without it. */
    printf("CONFIG_HAVE_NONSENSE=%d\n", CONFIG_HAVE_NONSENSE);
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (strcmp(CONFIG_STAMP, "configured-v1") != 0) failures++;
    if (CONFIG_HAVE_STDINT != 1) failures++;
    if (CONFIG_HAVE_NONSENSE != 0) failures++;
    printf("CONFIGURE_RAN=%s\n", failures == 0 ? "yes" : "no");
    printf("RESULT=%s\n", (failures == 0 && argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
