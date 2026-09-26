/* heartbeat — the payload of a `launch.mode: "service"` package.
 *
 * A .LEXE service is background BY DECLARATION. `lexe run` detaches it whether or
 * not the caller asked, because that is what the manifest says the application
 * IS — and the sandbox that supervises it deliberately does NOT die with the
 * process that started it, or a detached launch would not be detached.
 *
 * What it deliberately is NOT: a system daemon. It runs as the user, with the
 * same confinement as any other .LEXE application, with no privilege and no
 * network unless granted. It is not a systemd unit; whether it should be able to
 * become one is an open design question, not just an untested one (see
 * ../../../docs/ROADMAP.md §4).
 *
 * Everything it does is chosen to make service behaviour OBSERVABLE from outside,
 * because that is the hard part of testing a background process:
 *
 *   * it appends a line to $LEXE_APP_DATA/heartbeat.log every second, so
 *     "is it still running?" is answerable by reading a file rather than by
 *     inspecting a process tree, and "did it survive X?" is answerable by
 *     comparing counts before and after X;
 *   * it writes its own pid there first, so a test can act on the right process;
 *   * it handles SIGTERM by writing a final "stopped cleanly" line and exiting 0,
 *     so a clean shutdown is distinguishable from a kill -9 AFTER THE FACT. A
 *     service that cannot be told apart from one that crashed is a service whose
 *     restart behaviour cannot be tested;
 *   * `--beats <n>` makes it exit on its own after n beats, so a test that does
 *     not want to manage a process lifetime does not have to.
 *
 * It holds no state of its own beyond that log: a service example that needed
 * setting up would be testing the setup.
 */

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;

static void on_term(int signum) {
    (void)signum;
    stop_requested = 1;
}

static const char *env_or(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

/* Append one line, flushing and closing each time.
 *
 * Reopening per line rather than holding the file open is on purpose: a test may
 * read the log at any moment, including immediately after a kill -9, and buffered
 * output that never reached the disk would make a running service look stopped. */
static int log_line(const char *format, ...) {
    const char *data = getenv("LEXE_APP_DATA");
    if (data == NULL || data[0] == '\0') return -1;
    char path[2048];
    snprintf(path, sizeof path, "%s/heartbeat.log", data);
    FILE *log = fopen(path, "a");
    if (log == NULL) return -1;

    va_list args;
    va_start(args, format);
    vfprintf(log, format, args);
    va_end(args);
    fputc('\n', log);
    fflush(log);
    fclose(log);
    return 0;
}

int main(int argc, char **argv) {
    long beats = 0; /* 0 = until told to stop */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--beats") == 0 && i + 1 < argc) {
            beats = strtol(argv[i + 1], NULL, 10);
            if (beats < 0) beats = 0;
            if (beats > 3600) beats = 3600;
            ++i;
            continue;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("usage: heartbeat [--beats <n>]\n"
                   "  --beats <n>   exit after n beats instead of running until "
                   "SIGTERM\n"
                   "\n"
                   "Appends a line per second to $LEXE_APP_DATA/heartbeat.log, "
                   "so that a\n"
                   "test can observe a background process without inspecting the "
                   "process tree.\n");
            return 0;
        }
    }

    /* Default disposition is fine for SIGKILL (it cannot be caught, which is the
     * point of testing with it), but SIGTERM must be distinguishable. */
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_term;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    if (getenv("LEXE_APP_DATA") == NULL) {
        /* Not launched by .LEXE. Say so rather than failing obscurely: this
         * example is only meaningful inside the runtime that supervises it. */
        fprintf(stderr,
                "heartbeat: LEXE_APP_DATA is not set — this is a .LEXE service "
                "payload\n"
                "heartbeat: and has nowhere to record its heartbeat outside the "
                "runtime.\n");
        return 2;
    }

    log_line("started pid=%ld app=%s", (long)getpid(),
             env_or("LEXE_APP_ID", "(unset)"));
    printf("heartbeat: started as pid %ld\n", (long)getpid());
    fflush(stdout);

    long beat = 0;
    while (stop_requested == 0) {
        ++beat;
        log_line("beat %ld", beat);
        if (beats > 0 && beat >= beats) break;
        sleep(1);
    }

    if (stop_requested != 0) {
        /* The line that distinguishes a clean stop from a kill. */
        log_line("stopped cleanly after %ld beat(s)", beat);
        printf("heartbeat: stopped cleanly after %ld beat(s)\n", beat);
    } else {
        log_line("finished %ld requested beat(s)", beat);
        printf("heartbeat: finished %ld requested beat(s)\n", beat);
    }
    fflush(stdout);
    return 0;
}
