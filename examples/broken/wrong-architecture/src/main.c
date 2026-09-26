/* Deliberately wrong: this compiles for the HOST, while the manifest beside it
 * declares only aarch64. See ../README.md. */
#include <stdio.h>
int main(void) {
    puts("if you are reading this, a package that should have been refused ran");
    return 0;
}
