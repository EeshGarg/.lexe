/* One program, one build, many MANIFESTS.
 *
 * Every other recipe in this corpus varies the build. This one varies
 * `entrypoint.arguments`: the same product is launched with different argv, and
 * each launch is a separate specimen with its own declaration. That is the
 * cheapest honest way to cover the runtime behaviours a launcher has to survive
 * -- an unusual exit code, a fatal signal, output on stderr, an absent
 * environment variable, a file written into the working directory -- without
 * fourteen near-identical source trees.
 *
 * argv[1] selects the mode. Everything printed before the mode acts is printed
 * for every mode, so ARGC and the ARGV_n lines are a measurement of argv
 * delivery on every one of the fourteen specimens, not just the argv ones.
 *
 * Oracle rules observed here: KEY=value is deterministic, OBS_ is an
 * observation, RESULT is last. Nothing deterministic is a byte count or an
 * offset into this stream.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <unistd.h>
#endif

static const char *isa(void) {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#else
    return "unknown";
#endif
}

/* Pure integer work, so the VALUE is identical under every compiler; only the
 * wall time it takes depends on the machine, and wall time is never declared. */
static unsigned long spin(long rounds) {
    unsigned long h = 2166136261UL;
    long i;
    for (i = 0; i < rounds; i++) {
        h ^= (unsigned long)(i & 0xffff);
        h *= 16777619UL;
        h &= 0xffffffffUL;
        h ^= h >> 13;
    }
    return h;
}

static int known_mode(const char *m) {
    static const char *modes[] = {"report", "args", "exit", "crash", "abort",
                                  "stderr", "env", "write", "spin", "stdin", 0};
    int i;
    for (i = 0; modes[i]; i++)
        if (strcmp(m, modes[i]) == 0) return 1;
    return 0;
}

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    const char *mode = (argc > 1) ? argv[1] : "report";
    const char *arg2 = (argc > 2) ? argv[2] : "";
    int i, failures = 0;

    printf("FIXTURE_ID=%s\n", id ? id : "portable-run");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("MODE=%s\n", mode);
    printf("MODE_KNOWN=%s\n", known_mode(mode) ? "yes" : "no");
    printf("ARGC=%d\n", argc);
    for (i = 1; i < argc; i++)
        printf("ARGV_%d=%s\n", i, argv[i]);
    printf("BUILD_ISA=%s\n", isa());
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    if (!known_mode(mode)) failures++;

    if (strcmp(mode, "exit") == 0) {
        int code = atoi(arg2);
        printf("EXIT_REQUESTED=%d\n", code);
        printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
        return code;
    }

    if (strcmp(mode, "crash") == 0) {
        volatile int *p = (volatile int *)0;
        printf("FATAL_KIND=segv\n");
        printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
        /* Without this flush there is no output at all: stdout to a pipe is
         * block-buffered, and the specimen would be indistinguishable from one
         * that never reached main. The whole point of the specimen is a product
         * that DID start and then died. */
        fflush(stdout);
        *p = 1;
        return 0;                       /* not reached */
    }

    if (strcmp(mode, "abort") == 0) {
        printf("FATAL_KIND=abort\n");
        printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
        fflush(stdout);
        abort();
        return 0;                       /* not reached */
    }

    if (strcmp(mode, "stderr") == 0) {
        fputs("PORTABLE_RUN_STDERR_MARKER: this line is on fd 2\n", stderr);
        fflush(stderr);
        printf("STDERR_WRITTEN=yes\n");
        printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
        return 0;
    }

    if (strcmp(mode, "env") == 0) {
        const char *v = getenv(arg2);
        /* The NAME is deterministic; the VALUE is not, so it is not printed at
         * all rather than printed as an observation nobody can compare. */
        printf("ENV_NAME=%s\n", arg2);
        printf("ENV_PRESENT=%s\n", v ? "yes" : "no");
        printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
        return 0;
    }

    if (strcmp(mode, "write") == 0) {
        static const char banner[] = "portable-run-write-banner-v1\n";
        char back[64];
        FILE *f;
        int ok = 0;
        memset(back, 0, sizeof back);
        f = fopen(arg2, "w");
        if (f) {
            fputs(banner, f);
            if (fclose(f) == 0) {
                f = fopen(arg2, "r");
                if (f) {
                    if (fgets(back, (int)sizeof back, f))
                        ok = (strcmp(back, banner) == 0);
                    fclose(f);
                }
            }
        }
        printf("WRITE_PATH=%s\n", arg2);
        printf("WRITE_ROUNDTRIP=%s\n", ok ? "yes" : "no");
        if (!ok) failures++;
        printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
        return failures == 0 ? 0 : 4;
    }

    if (strcmp(mode, "spin") == 0) {
        long rounds = atol(arg2);
        unsigned long v = spin(rounds);
        printf("SPIN_ROUNDS=%ld\n", rounds);
        printf("SPIN_VALUE=%lu\n", v);
        printf("SPIN_NONZERO=%s\n", v != 0 ? "yes" : "no");
        printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
        return 0;
    }

    if (strcmp(mode, "stdin") == 0) {
        int c, saw = 0;
        while ((c = getchar()) != EOF) saw = 1;
        printf("STDIN_SAW_BYTES=%s\n", saw ? "yes" : "no");
        printf("STDIN_AT_EOF=%s\n", feof(stdin) ? "yes" : "no");
        printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
        return 0;
    }

    /* "report" and "args": the lines already printed above ARE the measurement. */
    printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 2;
}
