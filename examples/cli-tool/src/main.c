/*
 * cli-tool — a minimal .lexe CLI example.
 *
 * A tiny, dynamically linked command-line program: it reads its arguments and
 * uses libm (a real dependency beyond libc), so it is a genuine dynamic-ABI
 * example rather than a static hello-world. Build it in the Core 1 sysroot and
 * `lexe sdk verify` it, then `lexe build .` to package it.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: cli-tool <number> [<number> ...]\n");
        printf("prints the square root of each number.\n");
        return argc == 1 ? 0 : 2;
    }
    for (int i = 1; i < argc; ++i) {
        const double x = atof(argv[i]);
        if (x < 0) {
            fprintf(stderr, "cli-tool: %s is negative; skipping\n", argv[i]);
            continue;
        }
        printf("sqrt(%s) = %.6f\n", argv[i], sqrt(x));
    }
    return 0;
}
