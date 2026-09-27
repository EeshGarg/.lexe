/* A legitimate program whose recipe needs a compiler this host does not have.
 *
 * The specimen is not broken and the source is not broken: the recipe declares
 * `lexe-nonexistent-cc` in build.toolchain, which is a bare executable name
 * that resolves nowhere on this machine. A cross-compiler for an ISA the host
 * does not have installed is the same shape, and entirely ordinary.
 *
 * What the corpus records is that the tool really is absent (probed on PATH,
 * recorded in the index) and what running the declared build does about it. If
 * this program ever runs, something found a compiler, and that is worth knowing.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *id = getenv("FIXTURE_ID");
    printf("FIXTURE_ID=%s\n", id ? id : "portable-toolchain-absent");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("SHOULD_NOT_HAVE_BUILT=yes\n");
    printf("RESULT=PASS\n");
    return 0;
}
