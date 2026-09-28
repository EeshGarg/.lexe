/* Asynchronous procedure calls: a function queued onto ANOTHER thread, which runs
 * it only when that thread enters an alertable wait. There is no POSIX equivalent
 * to lean on -- the closest thing is a signal handler, and it is not close -- so
 * this is a mechanism a translation layer has to implement outright.
 *
 * The ordering here is not a race. The worker signals `ready` and then enters
 * SleepEx(..., TRUE); the APC is queued after `ready`, and an APC queued to a
 * thread that is not yet alertable is delivered as soon as it becomes alertable.
 * So whether the queue happens before or after the SleepEx begins, the result is
 * the same, which is exactly what makes this deterministic:
 *
 *   SleepEx must return WAIT_IO_COMPLETION (192), not 0, and it must return
 *   EARLY -- long before its 30-second timeout.
 *
 * A non-alertable SleepEx is checked too: the same APC must NOT run during it.
 */
#include "oracle_win.h"

static HANDLE ready;
static volatile LONG apc_ran = 0, apc_argument = 0, nonalert_slept = 0;
static volatile LONG sleepex_result = -1;
static DWORD apc_thread = 0, worker_thread = 0;

static void CALLBACK the_apc(ULONG_PTR arg) {
    InterlockedExchange(&apc_argument, (LONG)arg);
    apc_thread = GetCurrentThreadId();
    InterlockedIncrement(&apc_ran);
}

static DWORD WINAPI worker(LPVOID unused) {
    DWORD r;
    (void)unused;
    worker_thread = GetCurrentThreadId();
    /* First a NON-alertable sleep: an APC must not be delivered during it. */
    SetEvent(ready);
    Sleep(200);
    InterlockedExchange(&nonalert_slept, apc_ran ? 1 : 0);
    r = SleepEx(30000, TRUE);
    InterlockedExchange(&sleepex_result, (LONG)r);
    return 0;
}

int main(void) {
    HANDLE th;
    LARGE_INTEGER freq, t0, t1;
    double waited;
    orc_begin("pe-proc-apc");
    ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    orc_check("READY_EVENT", ready != NULL);
    th = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    orc_check("WORKER_THREAD", th != NULL);
    if (!th || !ready) return orc_end();

    orc_check("WORKER_REACHED_SLEEP", WaitForSingleObject(ready, 30000) == WAIT_OBJECT_0);
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    orc_check("QUEUE_USER_APC", QueueUserAPC(the_apc, th, (ULONG_PTR)0x5AFE) != 0);
    WaitForSingleObject(th, 60000);
    QueryPerformanceCounter(&t1);
    waited = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
    CloseHandle(th);
    CloseHandle(ready);

    orc_obs("WAITED_MS", "%.0f", waited);
    orc_kv("APC_RAN_COUNT", "%ld", (long)apc_ran);
    orc_kv("APC_ARGUMENT_HEX", "%04lx", (unsigned long)apc_argument);
    orc_kv("SLEEPEX_RETURN", "%ld", (long)sleepex_result);
    orc_kv("APC_RAN_DURING_NON_ALERTABLE_SLEEP", "%s", nonalert_slept ? "yes" : "no");
    orc_check("APC_RAN_EXACTLY_ONCE", apc_ran == 1);
    orc_check("APC_ARGUMENT_DELIVERED", apc_argument == 0x5AFE);
    orc_check("APC_RAN_ON_THE_TARGET_THREAD",
              apc_thread != 0 && apc_thread == worker_thread);
    orc_check("SLEEPEX_RETURNED_IO_COMPLETION", sleepex_result == (LONG)WAIT_IO_COMPLETION);
    orc_check("ALERTABLE_WAIT_ENDED_EARLY", waited < 25000.0);
    orc_check("NON_ALERTABLE_SLEEP_DID_NOT_RUN_IT", nonalert_slept == 0);
    return orc_end();
}
