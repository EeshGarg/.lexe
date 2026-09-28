/* Structured exception HANDLING, as opposed to the abnormal terminations in
 * w_abnormal.c. This is the machinery every Windows crash reporter is built on, and
 * the difference between a program that dies and a program that dies TIDILY.
 *
 * argv[1] picks the mode:
 *
 *   filter     SetUnhandledExceptionFilter, then an access violation. The filter
 *              must run, must see EXCEPTION_ACCESS_VIOLATION and the faulting
 *              address, and then calls ExitProcess(9) ITSELF -- so the observable
 *              outcome is a clean exit 9 with a complete oracle, not a crash. That
 *              is exactly what a crash handler does for real.
 *   vectored   a vectored handler installed FIRST must see the same exception
 *              BEFORE the unhandled filter does, and returning
 *              EXCEPTION_CONTINUE_SEARCH must then let the filter run. The ORDER is
 *              the property: VEH before the top-level filter.
 *   continue   a vectored handler for a RaiseException with a code of its own,
 *              returning EXCEPTION_CONTINUE_EXECUTION. RaiseException must then
 *              RETURN and the program must carry on and exit 0 normally. This is
 *              the one case where an exception is fully recovered from.
 *
 * All three write everything they know to the oracle file before doing anything
 * irreversible, because the file is flushed per line and is the only evidence that
 * survives.
 */
#include "oracle_win.h"

static volatile int *volatile target = 0;
static volatile LONG veh_hits = 0, filter_hits = 0;
static DWORD veh_code = 0, filter_code = 0;
static int veh_ran_before_filter = 0;

static LONG CALLBACK vectored(EXCEPTION_POINTERS *ep) {
    veh_code = ep->ExceptionRecord->ExceptionCode;
    InterlockedIncrement(&veh_hits);
    orc_kv("VEH_SAW_EXCEPTION", "yes");
    orc_kv("VEH_CODE", "0x%08lx", (unsigned long)veh_code);
    orc_kv("VEH_FILTER_HAD_ALREADY_RUN", "%s", filter_hits ? "yes" : "no");
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG CALLBACK vectored_continue(EXCEPTION_POINTERS *ep) {
    veh_code = ep->ExceptionRecord->ExceptionCode;
    InterlockedIncrement(&veh_hits);
    orc_kv("VEH_SAW_EXCEPTION", "yes");
    orc_kv("VEH_CODE", "0x%08lx", (unsigned long)veh_code);
    orc_kv("VEH_DECISION", "continue-execution");
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG WINAPI top_level(EXCEPTION_POINTERS *ep) {
    filter_code = ep->ExceptionRecord->ExceptionCode;
    veh_ran_before_filter = veh_hits > 0;
    InterlockedIncrement(&filter_hits);
    orc_kv("FILTER_RAN", "yes");
    orc_kv("FILTER_CODE", "0x%08lx", (unsigned long)filter_code);
    orc_kv("FILTER_SAW_ACCESS_VIOLATION", "%s",
           filter_code == (DWORD)EXCEPTION_ACCESS_VIOLATION ? "yes" : "no");
    orc_kv("FILTER_HAS_FAULT_ADDRESS", "%s",
           ep->ExceptionRecord->NumberParameters >= 2 ? "yes" : "no");
    orc_obs("FILTER_FAULT_ADDRESS", "%p", (void *)ep->ExceptionRecord->ExceptionAddress);
    orc_kv("VEH_RAN_BEFORE_THE_FILTER", "%s", veh_ran_before_filter ? "yes" : "no");
    orc_kv("HANDLER_CHOSE_EXIT_CODE", "%d", 9);
    orc_check("CRASH_WAS_HANDLED_NOT_FATAL", 1);
    orc_end();
    /* A real crash handler ends the process itself, having written its report. */
    ExitProcess(9);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "filter";
    orc_begin("pe-exception-handling");
    orc_kv("EXCEPTION_MODE", "%s", mode);

    if (strcmp(mode, "continue") == 0) {
        void *h = AddVectoredExceptionHandler(1, vectored_continue);
        orc_check("ADD_VECTORED_HANDLER", h != NULL);
        if (!h) return orc_end();
        orc_kv("ABOUT_TO_RAISE", "0xE0000099");
        /* Continuable on purpose: no EXCEPTION_NONCONTINUABLE, so a handler that
         * says "carry on" legitimately can. */
        RaiseException(0xE0000099u, 0, 0, NULL);
        orc_kv("RAISE_RETURNED", "yes");
        orc_kv("VEH_HITS", "%ld", (long)veh_hits);
        orc_check("EXCEPTION_FULLY_RECOVERED", veh_hits == 1);
        orc_check("EXECUTION_RESUMED_AFTER_THE_HANDLER", 1);
        RemoveVectoredExceptionHandler(h);
        return orc_end();
    }

    if (strcmp(mode, "vectored") == 0) {
        void *h = AddVectoredExceptionHandler(1, vectored);
        orc_check("ADD_VECTORED_HANDLER", h != NULL);
        if (!h) return orc_end();
    }
    orc_check("SET_UNHANDLED_EXCEPTION_FILTER",
              SetUnhandledExceptionFilter(top_level) != top_level);
    /* NOT EXPECT_DEATH: the fault is deliberate but the process does not die of
     * it. It is handled, reported and converted into a chosen exit code, which is
     * a different outcome from w_abnormal.c and the whole point of this specimen. */
    orc_kv("DELIBERATE_FAULT", "access-violation-to-be-handled");
    orc_kv("WORK_BEFORE_FAULT", "done");
    *target = 1;
    /* Unreachable: the filter exits the process. If it is ever reached, the
     * fault did not happen and the specimen must say so loudly. */
    orc_kv("FAULT_DID_NOT_HAPPEN", "yes");
    orc_check("FAULTED_AS_DECLARED", 0);
    return orc_end();
}
