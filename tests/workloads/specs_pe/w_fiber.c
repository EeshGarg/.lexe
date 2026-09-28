/* Fibers: cooperative, user-scheduled execution contexts inside one thread.
 *
 * Fibers are in this corpus because real Windows games use them -- a job system
 * built on fibers is a standard engine design -- and because they are the one
 * place where a translation layer has to reproduce a CONTEXT SWITCH it performs
 * itself, stack and all, rather than delegating to the host scheduler.
 *
 * The switching order is fixed by the program, so the sequence string is exactly
 * determined: the main fiber hands control to A, A hands it back, main hands it to
 * B, B hands it back, then A again, then main finishes.
 *
 *   expected FIBER_SEQUENCE = mAmBmAm
 *
 * Every fiber also records which OS thread it ran on, and all of them must be the
 * same thread: a fiber that migrated would mean the implementation is threads in
 * disguise.
 */
#include "oracle_win.h"

static void *main_fiber = NULL;
static void *fiber_a = NULL;
static void *fiber_b = NULL;
static char sequence[32];
static unsigned seq_len = 0;
static DWORD thread_of_a = 0, thread_of_b = 0, thread_of_main = 0;
static unsigned a_entries = 0, b_entries = 0;

static void note(char c) {
    if (seq_len + 1 < sizeof sequence) sequence[seq_len++] = c;
    sequence[seq_len] = 0;
}

static void WINAPI proc_a(LPVOID unused) {
    (void)unused;
    for (;;) {
        a_entries++;
        thread_of_a = GetCurrentThreadId();
        note('A');
        SwitchToFiber(main_fiber);
    }
}

static void WINAPI proc_b(LPVOID unused) {
    (void)unused;
    for (;;) {
        b_entries++;
        thread_of_b = GetCurrentThreadId();
        note('B');
        SwitchToFiber(main_fiber);
    }
}

int main(void) {
    orc_begin("pe-proc-fibers");
    sequence[0] = 0;
    thread_of_main = GetCurrentThreadId();

    main_fiber = ConvertThreadToFiber(NULL);
    orc_check("CONVERT_THREAD_TO_FIBER", main_fiber != NULL);
    if (!main_fiber) { orc_werr_now("CONVERT_ERROR"); return orc_end(); }

    fiber_a = CreateFiber(64 * 1024, proc_a, NULL);
    fiber_b = CreateFiber(64 * 1024, proc_b, NULL);
    orc_check("CREATE_FIBER_A", fiber_a != NULL);
    orc_check("CREATE_FIBER_B", fiber_b != NULL);
    if (!fiber_a || !fiber_b) { orc_werr_now("CREATE_FIBER_ERROR"); return orc_end(); }

    note('m'); SwitchToFiber(fiber_a);
    note('m'); SwitchToFiber(fiber_b);
    note('m'); SwitchToFiber(fiber_a);
    note('m');

    orc_kv("FIBER_SEQUENCE", "%s", sequence);
    orc_kv("FIBER_A_ENTRIES", "%u", a_entries);
    orc_kv("FIBER_B_ENTRIES", "%u", b_entries);
    orc_check("SWITCHING_ORDER_AS_PROGRAMMED", strcmp(sequence, "mAmBmAm") == 0);
    orc_check("FIBER_A_RESUMED_NOT_RESTARTED", a_entries == 2);
    orc_check("ALL_FIBERS_ON_ONE_THREAD",
              thread_of_a == thread_of_main && thread_of_b == thread_of_main);

    DeleteFiber(fiber_a);
    DeleteFiber(fiber_b);
    orc_check("CONVERT_FIBER_TO_THREAD", ConvertFiberToThread() != 0);
    return orc_end();
}
