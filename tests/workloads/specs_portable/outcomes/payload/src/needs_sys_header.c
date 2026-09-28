/* Needs a system header that is not installed on this host.
 *
 * Not a broken package: this is what every package that depends on a -dev
 * package looks like on a machine that has not got it. The declared toolchain is
 * present and correct -- cc and make are both there -- and the build still
 * cannot proceed, which is a different failure from a missing TOOL and has to be
 * reported differently. gtk/gtk.h is chosen because it is a header nobody has by
 * accident and nothing else in the corpus depends on it.
 */
#include <stdio.h>
#include <gtk/gtk.h>

int main(void) {
    printf("FIXTURE_ID=unreachable\n");
    return 0;
}
