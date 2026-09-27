/* This is where the build stops, and it stops for an ordinary reason rather than
 * a contrived one: the function is declared to return a struct that was never
 * defined, which is exactly what a missing header looks like. A syntax error
 * would be less useful -- half of real build failures are a type or a header
 * that is not there on THIS machine.
 *
 * The specimen's property is that the failure happens PART-WAY: first.o and
 * second.o already exist when the compiler stops, so there is a partial build
 * tree and no entrypoint, and something has to decide what that means.
 */
#include "missing_header_that_does_not_exist.h"

unsigned long third_value(void) { return 303; }
