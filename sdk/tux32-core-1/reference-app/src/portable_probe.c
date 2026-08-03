/*
 * Tux32 Core 1 reference application (portability milestone).
 *
 * A deliberately small but NON-TRIVIAL, dynamically linked program. It is the
 * artifact the cross-distribution proof carries unchanged from a newer build
 * host to an older conforming runtime. It is intentionally NOT a static
 * hello-world: it exercises the real dynamic ABI and the Core 1 runtime
 * contract an actual application depends on.
 *
 *   - It links DYNAMICALLY against the host glibc and libm. `sqrt`/`sin`/`pow`
 *     force a real DT_NEEDED on libm.so.6 beyond bare libc, so the binary
 *     genuinely exercises the dynamic-linking contract rather than sidestepping
 *     it with a fully static image.
 *   - It keeps PERSISTENT state under $LEXE_APP_DATA (a launch counter that must
 *     survive across launches, updates and rollback).
 *   - It writes a DISPOSABLE artifact under $LEXE_APP_CACHE.
 *   - It uses a PRIVATE, per-launch scratch file under $TMPDIR.
 *   - It prints its identity ($LEXE_APP_ID) and a libm-derived result.
 *
 * The runtime provides these via a sanitized environment (see docs/ISOLATION.md
 * and src/core/isolation.cpp). Outside the sandbox the variables may be unset,
 * so every one has a safe fallback and the program still runs for local testing.
 *
 * To be Core 1 conformant it MUST be built against a glibc no newer than the
 * ceiling (2.31). Build it in the Core 1 sysroot (sdk/tux32-core-1/
 * build-in-sysroot.sh) and confirm with `lexe sdk verify` before packaging: a
 * binary built on a newer host will import newer glibc symbols and be rejected.
 */

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Create `dir` if absent (like `mkdir -p` for a single level). Returns 0 on
 * success or when it already exists. */
static int ensure_dir(const char *dir) {
    if (mkdir(dir, 0700) == 0) return 0;
    return (errno == EEXIST) ? 0 : -1;
}

/* An environment value, or `fallback` when unset/empty. */
static const char *env_or(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return (v != NULL && v[0] != '\0') ? v : fallback;
}

/* Read a non-negative integer from `path`; 0 when the file is absent/empty. */
static long read_counter(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return 0;
    long value = 0;
    if (fscanf(f, "%ld", &value) != 1 || value < 0) value = 0;
    fclose(f);
    return value;
}

/* A small libm-driven computation, purely to exercise a real dynamic dependency
 * beyond libc: a numeric estimate of pi via sqrt over a unit quarter-circle. */
static double estimate_pi(void) {
    const int steps = 100000;
    double area = 0.0;
    int i;
    for (i = 0; i < steps; ++i) {
        double x = (i + 0.5) / steps;
        area += sqrt(1.0 - pow(x, 2.0)) / steps;
    }
    return 4.0 * area;
}

int main(void) {
    const char *app_id = env_or("LEXE_APP_ID", "org.lexe.reference.probe");
    const char *data_dir = env_or("LEXE_APP_DATA", env_or("HOME", "."));
    const char *cache_dir = env_or("LEXE_APP_CACHE", ".");
    const char *tmp_dir = env_or("TMPDIR", "/tmp");

    /* Persistent launch counter under the app's data root. */
    char state_path[4096];
    snprintf(state_path, sizeof(state_path), "%s/state.txt", data_dir);
    long launches = read_counter(state_path) + 1;

    if (ensure_dir(data_dir) != 0) {
        fprintf(stderr, "probe: cannot use data dir %s: %s\n", data_dir,
                strerror(errno));
        return 1;
    }
    FILE *state = fopen(state_path, "w");
    if (state == NULL) {
        fprintf(stderr, "probe: cannot write %s: %s\n", state_path,
                strerror(errno));
        return 1;
    }
    fprintf(state, "%ld\n", launches);
    fclose(state);

    /* Disposable cache artifact. */
    (void)ensure_dir(cache_dir);
    char cache_path[4096];
    snprintf(cache_path, sizeof(cache_path), "%s/last-run.txt", cache_dir);
    FILE *cache = fopen(cache_path, "w");
    if (cache != NULL) {
        fprintf(cache, "launch %ld\n", launches);
        fclose(cache);
    }

    /* Private, per-launch scratch file (tmpfs; discarded when the launch ends). */
    char tmp_path[4096];
    snprintf(tmp_path, sizeof(tmp_path), "%s/probe-scratch.txt", tmp_dir);
    FILE *scratch = fopen(tmp_path, "w");
    if (scratch != NULL) {
        fprintf(scratch, "scratch for launch %ld\n", launches);
        fclose(scratch);
    }

    const double pi = estimate_pi();

    printf("Tux32 Core 1 reference probe\n");
    printf("  app id:        %s\n", app_id);
    printf("  launch count:  %ld  (persisted at %s)\n", launches, state_path);
    printf("  cache file:    %s\n", cache_path);
    printf("  temp file:     %s\n", tmp_path);
    printf("  libm estimate: pi ~= %.6f (dynamic libm)\n", pi);
    printf("  status:        OK\n");
    return 0;
}
