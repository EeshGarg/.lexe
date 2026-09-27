/* Installs a handler for SIGUSR1 and SIGUSR2 with SA_SIGINFO, raises both, and
 * reports what the handler saw. Handler writes nothing; main reports, so the
 * output stays async-signal-safe. */
#include "oracle.h"
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t got_usr1 = 0, got_usr2 = 0, last_code = 0;

static void handler(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    if (sig == SIGUSR1) got_usr1++;
    if (sig == SIGUSR2) got_usr2++;
    if (info) last_code = info->si_code;
}

int main(void) {
    struct sigaction sa;
    orc_begin("linux-signal-catch-report");
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    orc_check("SIGACTION_USR1", sigaction(SIGUSR1, &sa, NULL) == 0);
    orc_check("SIGACTION_USR2", sigaction(SIGUSR2, &sa, NULL) == 0);
    raise(SIGUSR1);
    raise(SIGUSR2);
    raise(SIGUSR1);
    orc_kv("USR1_COUNT", "%d", (int)got_usr1);
    orc_kv("USR2_COUNT", "%d", (int)got_usr2);
    orc_kv("SI_CODE_IS_TKILL_OR_USER", "%s",
           (last_code == SI_TKILL || last_code == SI_USER) ? "yes" : "no");
    orc_check("SURVIVED_CAUGHT_SIGNALS", 1);
    return orc_end();
}
