/* A tiny cooperative child used as an exec/fork target by several specimens.
 * argv[1] = role tag, argv[2] = exit code to use. */
#include "oracle.h"
#include <unistd.h>

int main(int argc, char **argv) {
    const char *role = argc > 1 ? argv[1] : "child";
    int code = argc > 2 ? atoi(argv[2]) : 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("CHILD_ROLE=%s\n", role);
    printf("CHILD_ARGC=%d\n", argc);
    printf("CHILD_EXIT_INTENT=%d\n", code);
    fflush(stdout);
    return code;
}
