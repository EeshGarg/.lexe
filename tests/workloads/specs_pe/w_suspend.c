/* CREATE_SUSPENDED, SuspendThread and ResumeThread, and the suspend COUNT.
 *
 * Creating a thread suspended and resuming it later is how real Windows software
 * sets a thread up -- priority, affinity, a name, an injected hook -- before it can
 * run a single instruction. The count matters: suspends nest, and a thread
 * suspended twice needs resuming twice. A runtime that treats suspend as a boolean
 * lets a thread run one resume too early, which is the bug this pins down.
 *
 *   created suspended        -> must NOT have run after 250 ms
 *   ResumeThread             -> returns the PREVIOUS count, 1
 *   suspended twice more     -> counts 1 then 2 returned
 *   one resume               -> still suspended, still must not progress
 *   second resume            -> runs to completion
 */
#include "oracle_win.h"

static volatile LONG phase = 0;
static volatile LONG ticks = 0;

static DWORD WINAPI worker(LPVOID unused) {
    (void)unused;
    InterlockedExchange(&phase, 1);
    for (;;) {
        InterlockedIncrement(&ticks);
        if (phase == 2) break;
        Sleep(1);
    }
    InterlockedExchange(&phase, 3);
    return 0;
}

int main(void) {
    HANDLE th;
    DWORD prev;
    LONG at_gate;
    orc_begin("pe-proc-suspended-thread");
    th = CreateThread(NULL, 0, worker, NULL, CREATE_SUSPENDED, NULL);
    orc_check("CREATE_SUSPENDED", th != NULL);
    if (!th) { orc_werr_now("CREATE_ERROR"); return orc_end(); }

    Sleep(250);
    orc_kv("PHASE_WHILE_SUSPENDED", "%ld", (long)phase);
    orc_check("DID_NOT_RUN_WHILE_SUSPENDED", phase == 0);

    prev = ResumeThread(th);
    orc_kv("FIRST_RESUME_PREVIOUS_COUNT", "%ld", (long)prev);
    orc_check("FIRST_RESUME_REPORTED_COUNT_ONE", prev == 1);
    {
        int spins = 0;
        while (phase == 0 && spins < 5000) { Sleep(1); spins++; }
    }
    orc_check("RAN_AFTER_RESUME", phase == 1);

    /* Nested suspends: two of them, so one resume must not be enough. */
    prev = SuspendThread(th);
    orc_kv("SUSPEND_ONE_PREVIOUS_COUNT", "%ld", (long)prev);
    prev = SuspendThread(th);
    orc_kv("SUSPEND_TWO_PREVIOUS_COUNT", "%ld", (long)prev);
    orc_check("SUSPEND_COUNT_NESTS", prev == 1);

    Sleep(150);
    at_gate = ticks;
    prev = ResumeThread(th);
    orc_kv("RESUME_FROM_TWO_PREVIOUS_COUNT", "%ld", (long)prev);
    orc_check("RESUME_FROM_TWO_REPORTED_TWO", prev == 2);
    Sleep(150);
    orc_check("STILL_SUSPENDED_AFTER_ONE_RESUME", ticks == at_gate);

    prev = ResumeThread(th);
    orc_kv("FINAL_RESUME_PREVIOUS_COUNT", "%ld", (long)prev);
    orc_check("FINAL_RESUME_REPORTED_ONE", prev == 1);

    InterlockedExchange(&phase, 2);
    orc_check("THREAD_JOINED", WaitForSingleObject(th, 30000) == WAIT_OBJECT_0);
    orc_kv("FINAL_PHASE", "%ld", (long)phase);
    orc_obs("TICKS", "%ld", (long)ticks);
    orc_check("THREAD_COMPLETED", phase == 3);
    orc_check("MADE_PROGRESS_AFTER_FULL_RESUME", ticks > at_gate);
    {
        DWORD code = 1;
        orc_check("GET_EXIT_CODE_THREAD", GetExitCodeThread(th, &code) != 0);
        orc_kv("THREAD_EXIT_CODE", "%lu", (unsigned long)code);
    }
    CloseHandle(th);
    return orc_end();
}
