/* A child that terminates abnormally, on purpose, with an access violation. Its
 * parent must survive it and be able to report the status. The oracle file is
 * flushed per line, so everything up to the fault is on disk. */
#include "t_common.h"

static volatile int *volatile target = 0;

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    orc_begin_fixed("t_crash_handler");
    orc_kv("NODE", "crash_handler");
    orc_kv("WORK_BEFORE_FAULT", "done");
    orc_expect_death("access-violation");
    *target = 1;
    orc_kv("UNREACHABLE", "yes");
    orc_check("DIED", 0);
    return orc_end();
}
