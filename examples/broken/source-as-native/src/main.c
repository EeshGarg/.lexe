/* Deliberately the ENTRYPOINT of a package that declares applicationType
 * "native" — which is the honest mistake the `portable` type exists to serve.
 * See ../README.md. */
#include <stdio.h>
int main(void) {
    puts("source code is not a compiled program");
    return 0;
}
