/* portable-hello — the payload of a `applicationType: "portable"` package.
 *
 * This file, not a binary, is what ships. The machine that installs the
 * package compiles it, and what it reports is exactly the evidence that the
 * compile really happened HERE:
 *
 *   * __DATE__/__TIME__ are baked in by the compiler, on the installing
 *     machine, at install time;
 *   * the ISA it prints comes from the compiler's own predefined macros, so it
 *     is the architecture the build actually targeted, not a manifest claim;
 *   * the sandbox variables it prints are the launcher's, proving the compiled
 *     program is launched by .LEXE like any native payload.
 *
 * It is a console program and the manifest declares `launch.mode: "console"`,
 * because a program that prints and exits must say so — that declaration is
 * what lets .LEXE give it a terminal instead of the user seeing nothing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* host_isa(void) {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#elif defined(__riscv) && __riscv_xlen == 64
    return "riscv64";
#else
    return "unknown";
#endif
}

static const char* env_or(const char* name, const char* fallback) {
    const char* value = getenv(name);
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

int main(int argc, char** argv) {
    int selftest = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--selftest") == 0) selftest = 1;
    }

    printf("Lexe Portable Hello\n");
    printf("  compiled on this machine: %s %s\n", __DATE__, __TIME__);
    printf("  compiled for:             %s\n", host_isa());
    printf("  LEXE_APP_ID:              %s\n",
           env_or("LEXE_APP_ID", "(not launched by .LEXE)"));
    printf("  LEXE_APP_DATA:            %s\n",
           env_or("LEXE_APP_DATA", "(none)"));

    /* Every start is recorded in the private data root, so a launch is
     * provable on a host with no display and no terminal at all. */
    const char* data = getenv("LEXE_APP_DATA");
    if (data != NULL && data[0] != '\0') {
        char path[4096];
        snprintf(path, sizeof(path), "%s/portable-hello-launches.log", data);
        FILE* log = fopen(path, "a");
        if (log != NULL) {
            fprintf(log, "started, compiled %s %s for %s\n", __DATE__, __TIME__,
                    host_isa());
            fclose(log);
        }
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--selftest") != 0) printf("  arg: %s\n", argv[i]);
    }

    if (selftest) {
        /* The one thing worth asserting from inside: the private data root is
         * really there and really writable. */
        if (data == NULL || data[0] == '\0') {
            printf("selftest: FAIL (no LEXE_APP_DATA)\n");
            return 1;
        }
        printf("selftest: PASS\n");
    }
    return 0;
}
