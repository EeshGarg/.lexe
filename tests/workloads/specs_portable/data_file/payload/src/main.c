/* A product that needs a file at RUN time, found three different ways.
 *
 * This is the same question as the rpath family asks of libraries, asked of
 * data, and it has the same three answers:
 *
 *   proc-self-exe   ask the kernel where this process's image is, and look
 *                   beside it. Survives being installed anywhere.
 *   baked-abs-path  compile the build directory into the binary. Works
 *                   perfectly until the build directory is gone, which is
 *                   always, and the failure is a missing file rather than a
 *                   missing library so no loader diagnostic appears.
 *   cwd-relative    look relative to the current working directory, i.e. hope
 *                   the user launched it from the right place. Fails even in
 *                   the tree that built it as soon as the launcher chooses its
 *                   own working directory -- which every launcher does.
 *
 * The resolved path is an OBS_ observation because it contains an absolute path
 * that differs on every machine. What is DECLARED is whether the file was found
 * and what its first line said.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef LOOKUP_NAME
#define LOOKUP_NAME "unset"
#endif

static void chomp(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

/* payload/bin/<prog> -> payload/share/message.txt, via /proc/self/exe. */
static int resolve_via_proc(char *out, size_t cap) {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    char *slash;
    if (n <= 0) return 0;
    buf[n] = '\0';
    slash = strrchr(buf, '/');
    if (!slash) return 0;
    *slash = '\0';                      /* .../payload/bin */
    slash = strrchr(buf, '/');
    if (!slash) return 0;
    *slash = '\0';                      /* .../payload */
    if (strlen(buf) + sizeof("/share/message.txt") > cap) return 0;
    strcpy(out, buf);
    strcat(out, "/share/message.txt");
    return 1;
}

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    char path[4096];
    char line[256];
    FILE *f;
    int resolved = 0, found = 0, token_ok = 0;

    memset(path, 0, sizeof path);
    memset(line, 0, sizeof line);

    printf("FIXTURE_ID=%s\n", id ? id : "portable-data-file");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("LOOKUP=%s\n", LOOKUP_NAME);

#if defined(LOOKUP_PROC_SELF_EXE)
    resolved = resolve_via_proc(path, sizeof path);
#elif defined(LOOKUP_BAKED_ABS)
    /* DATA_DIR is an absolute path handed in by the Makefile at compile time.
     * It is printed as a DECLARED value, not an observation: the whole property
     * of this variant is that a build-tree path is now a constant in the
     * product, and hiding it behind OBS_ would hide exactly that. */
    printf("BAKED_DATA_DIR=%s\n", DATA_DIR);
    if (strlen(DATA_DIR) + sizeof("/message.txt") <= sizeof path) {
        strcpy(path, DATA_DIR);
        strcat(path, "/message.txt");
        resolved = 1;
    }
#elif defined(LOOKUP_CWD)
    strcpy(path, "share/message.txt");
    resolved = 1;
#else
#error "no LOOKUP_ mode selected"
#endif

    printf("PATH_RESOLVED=%s\n", resolved ? "yes" : "no");
    printf("OBS_DATA_PATH=%s\n", path[0] ? path : "<unresolved>");

    if (resolved) {
        f = fopen(path, "r");
        if (f) {
            found = 1;
            if (fgets(line, (int)sizeof line, f)) chomp(line);
            fclose(f);
        }
    }
    printf("DATA_FOUND=%s\n", found ? "yes" : "no");
    token_ok = (strcmp(line, "portable-data-file-token-1") == 0);
    printf("DATA_TOKEN=%s\n", line[0] ? line : "<none>");
    printf("DATA_TOKEN_OK=%s\n", token_ok ? "yes" : "no");
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    (void)argc; (void)argv;
    printf("RESULT=%s\n", (found && token_ok) ? "PASS" : "FAIL");
    return (found && token_ok) ? 0 : 3;
}
