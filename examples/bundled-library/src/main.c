#include "greeting.h"

#include <stdio.h>

/* Calls into a companion shared library (libgreeting.so) that is bundled inside
 * the package next to the executable. The dependency engine classifies it as a
 * "bundle" dependency; RPATH $ORIGIN/../lib lets it load from the payload. */
int main(void) {
    printf("%s\n", greeting());
    return 0;
}
