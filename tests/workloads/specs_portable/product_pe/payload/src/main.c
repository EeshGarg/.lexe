/* A build that succeeds and produces something that is NOT a host-ISA
 * executable.
 *
 * The source is an ordinary console C program. The recipe compiles it with
 * x86_64-w64-mingw32-gcc, so the product at the declared entrypoint path is a
 * PE32+ Windows executable: a real, well-formed, runnable program -- just not
 * one this kernel can exec. `file(1)` says so, and the corpus records what it
 * says.
 *
 * This is not a hostile package and not a malformed one. It is the shape a
 * publisher produces by cross-compiling by accident, or by declaring the wrong
 * architectures, and the only way to find out what a runtime does about a
 * successful build whose product is foreign is to have one.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *id = getenv("FIXTURE_ID");
    printf("FIXTURE_ID=%s\n", id ? id : "portable-product-pe");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("PRODUCT_FORMAT=pe32plus\n");
    printf("RESULT=PASS\n");
    return 0;
}
