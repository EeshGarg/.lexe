/* windows-hello — the payload of an `applicationType: "windows"` package.
 *
 * It is an ordinary Windows console program, compiled to a PE with MinGW. The
 * point of the example is that .LEXE never pretends this is a Linux program:
 * the manifest declares a foreign-OS payload, verification proves the bytes
 * really are a runnable Windows executable, and the resolver picks Wine or
 * Proton — with the whole thing refused if the host has neither.
 *
 * What it prints is chosen to be evidence rather than decoration:
 *
 *   * the Windows API reports the "OS version" it thinks it is running on,
 *     which comes from the compatibility layer, not from Linux;
 *   * LEXE_APP_ID and LEXE_APP_DATA show .LEXE launched it and gave it a
 *     private data root — the environment crosses the Wine boundary intact;
 *   * it writes into that data root and reads it back, which is where Wine
 *     also puts its own prefix, so "the sandbox is real and writable" is
 *     testable from inside a Windows process.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

static const char* env_or(const char* name, const char* fallback) {
    const char* value = getenv(name);
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

int main(int argc, char** argv) {
    int selftest = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--selftest") == 0) selftest = 1;
    }

    printf("Lexe Windows Hello\n");
    printf("  this is a Windows PE running on Linux\n");

    DWORD version = GetVersion();
    printf("  Windows API version:  %u.%u\n", (unsigned)(LOBYTE(LOWORD(version))),
           (unsigned)(HIBYTE(LOWORD(version))));

    char module[MAX_PATH];
    if (GetModuleFileNameA(NULL, module, (DWORD)sizeof(module)) != 0) {
        printf("  module path:          %s\n", module);
    }

    const char* id = env_or("LEXE_APP_ID", "(not launched by .LEXE)");
    const char* data = env_or("LEXE_APP_DATA", "");
    printf("  LEXE_APP_ID:          %s\n", id);
    printf("  LEXE_APP_DATA:        %s\n", data[0] != '\0' ? data : "(none)");

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--selftest") != 0) printf("  arg: %s\n", argv[i]);
    }

    /* Every start is recorded in the private data root, so a launch is
     * provable on a host with no terminal at all. The path is a Unix path in
     * a Windows process: Wine maps it through its Z: drive, which is exactly
     * the boundary this example exists to show working. */
    if (data[0] != '\0') {
        char path[4096];
        snprintf(path, sizeof(path), "%s/windows-hello-launches.log", data);
        FILE* log = fopen(path, "a");
        if (log != NULL) {
            fprintf(log, "started as a Windows PE under a compatibility layer\n");
            fclose(log);
        } else if (selftest) {
            printf("selftest: FAIL (cannot write to LEXE_APP_DATA)\n");
            return 1;
        }
    } else if (selftest) {
        printf("selftest: FAIL (no LEXE_APP_DATA)\n");
        return 1;
    }

    if (selftest) printf("selftest: PASS\n");
    return 0;
}
