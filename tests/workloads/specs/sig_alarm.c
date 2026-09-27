/* A bounded run driven by SIGALRM rather than sleep: sets a 1s alarm, blocks in
 * pause(), reports that the alarm arrived and how many times pause returned. */
#include "oracle.h"
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t fired = 0;

static void on_alarm(int s) { (void)s; fired = 1; }

int main(void) {
    struct sigaction sa;
    orc_begin("linux-signal-alarm-bounded");
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigemptyset(&sa.sa_mask);
    orc_check("SIGACTION_ALRM", sigaction(SIGALRM, &sa, NULL) == 0);
    alarm(1);
    pause();
    orc_kv("ALARM_FIRED", "%s", fired ? "yes" : "no");
    orc_check("ALARM_DELIVERED", fired == 1);
    orc_kv("DURATION_CLASS", "second");
    return orc_end();
}
