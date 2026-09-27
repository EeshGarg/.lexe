/* Abnormal termination, four ways, selected by argv[1]:
 *
 *   av        an access violation (write through a volatile null pointer)
 *   abort     the C runtime abort()
 *   raise     RaiseException with a custom code and no handler
 *   terminate TerminateProcess on itself with a chosen code
 *
 * Each writes EXPECT_DEATH to the oracle FILE before dying, and the file is
 * flushed per line, so the evidence survives the fault. What exit status a
 * translation layer reports for each of these is NOT declared here -- it is
 * recorded per layer, because that mapping is a property of the layer. */
#include "oracle_win.h"

static volatile int *volatile target = 0;

int main(int argc, char **argv) {
    const char *how = argc > 1 ? argv[1] : "av";
    orc_begin("pe-outcome-abnormal");
    orc_kv("ABNORMAL_MODE", "%s", how);
    orc_kv("WORK_BEFORE_FAULT", "done");
    if (strcmp(how, "abort") == 0) {
        orc_expect_death("abort");
        orc_ekv("STDERR_BEFORE_ABORT", "invariant violated");
        abort();
    } else if (strcmp(how, "raise") == 0) {
        /* On Windows this ends the process. Under Wine with no debugger attached
         * the unhandled-exception path RETURNS and execution resumes, which is a
         * property of the layer, not a fault in this program -- so record which
         * of the two happened rather than asserting one of them. Measured, not
         * assumed: see the corpus README. */
        orc_expect_death("raise-exception-0xE0000042");
        RaiseException(0xE0000042u, EXCEPTION_NONCONTINUABLE, 0, NULL);
        orc_kv("RAISE_RETURNED", "yes");
        orc_kv("PROCESS_SURVIVED_UNHANDLED_EXCEPTION", "yes");
        orc_check("REPORTED_EITHER_WAY", 1);
        return orc_end();
    } else if (strcmp(how, "terminate") == 0) {
        orc_expect_death("terminate-process-137");
        TerminateProcess(GetCurrentProcess(), 137);
    } else {
        orc_expect_death("access-violation");
        *target = 1;
    }
    orc_kv("UNREACHABLE", "yes");
    orc_check("DIED", 0);
    return orc_end();
}
