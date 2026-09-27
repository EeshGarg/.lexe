/* An event object used to hand work between two threads in a fixed order, so the
 * output is deterministic despite being concurrent: the worker cannot write its
 * line until the main thread signals, and the main thread cannot finish until the
 * worker signals back. */
#include "oracle_win.h"

static HANDLE go, done;
static volatile LONG worker_ran = 0;

static DWORD WINAPI worker(LPVOID unused) {
    (void)unused;
    if (WaitForSingleObject(go, 30000) != WAIT_OBJECT_0) return 1;
    InterlockedExchange(&worker_ran, 1);
    SetEvent(done);
    return 0;
}

int main(void) {
    HANDLE th;
    orc_begin("pe-sync-event-handoff");
    go = CreateEventW(NULL, FALSE, FALSE, NULL);
    done = CreateEventW(NULL, FALSE, FALSE, NULL);
    orc_check("EVENTS_CREATED", go != NULL && done != NULL);
    th = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    orc_check("THREAD_CREATED", th != NULL);
    orc_kv("WORKER_RAN_BEFORE_SIGNAL", "%s", worker_ran ? "yes" : "no");
    SetEvent(go);
    orc_check("HANDOFF_COMPLETED", WaitForSingleObject(done, 30000) == WAIT_OBJECT_0);
    orc_kv("WORKER_RAN_AFTER_SIGNAL", "%s", worker_ran ? "yes" : "no");
    if (th) { WaitForSingleObject(th, 30000); CloseHandle(th); }
    CloseHandle(go); CloseHandle(done);
    return orc_end();
}
