/* A build that succeeds and produces a shared library where the manifest says
 * the entrypoint is.
 *
 * This one is a single character away from correct: a recipe that passes
 * -shared where it meant to link an executable. The file that results is a
 * perfectly good ELF -- ET_DYN, correct machine, correct ABI -- with no program
 * interpreter and no usable entry point, so exec of it fails at run time rather
 * than at build time. That gap between "the build succeeded" and "the product
 * can be launched" is the property.
 *
 * It also has an exported symbol and a constructor, so it is demonstrably a
 * real library and not a broken file.
 */
#include <stdio.h>

__attribute__((constructor)) static void announce(void) {
    printf("SO_CONSTRUCTOR_RAN=yes\n");
}

int payload_entry(void) {
    printf("FIXTURE_ID=portable-product-shared-object\n");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("RESULT=PASS\n");
    return 0;
}
