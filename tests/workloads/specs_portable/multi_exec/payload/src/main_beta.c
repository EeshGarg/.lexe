/* Program beta of three built by one package. Only the declared entrypoint of a
 * given manifest is launched; the other two are extra products that must exist. */
#include <stdio.h>
#include "common.h"

int main(int argc, char **argv) {
    emit_common("beta", "portable-multi-beta");
    printf("ARGC=%d\n", argc);
    printf("RESULT=%s\n", (argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
