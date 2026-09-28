/* Compiles cleanly. Does not link.
 *
 * A build failure at the LINK step is a different shape from a build failure at
 * the compile step: every object file exists, every translation unit was
 * accepted, and the diagnostic names a symbol rather than a file and a line. A
 * consumer that scrapes "error:" out of compiler output finds nothing here --
 * GNU ld says "undefined reference to".
 */
#include <stdio.h>
#include <stdlib.h>

/* Declared, used, and defined nowhere in this package. */
extern int portable_symbol_that_does_not_exist(int x);

int main(void) {
    const char *id = getenv("FIXTURE_ID");
    printf("FIXTURE_ID=%s\n", id ? id : "portable-outcome-link-fails");
    printf("VALUE=%d\n", portable_symbol_that_does_not_exist(1));
    printf("RESULT=PASS\n");
    return 0;
}
