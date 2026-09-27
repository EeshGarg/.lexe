/* The helper that outlives its parents. It sleeps for argv[1] milliseconds --
 * long enough that the launcher, bootstrap and main are all gone before it
 * finishes -- and only then writes its completion line.
 *
 * This is the single most important evidence file in the tree family: if
 * t_helper.oracle contains HELPER_COMPLETED=yes, the work survived the exit of
 * everything that started it. If it contains only the opening lines, something
 * killed it when its parent went away. */
#include "t_common.h"

int main(int argc, char **argv) {
    DWORD ms = argc > 1 ? (DWORD)strtoul(argv[1], NULL, 10) : 1500;
    orc_begin_fixed("t_helper");
    orc_kv("NODE", "helper");
    orc_kv("SLEEP_MS", "%lu", (unsigned long)ms);
    orc_kv("HELPER_STARTED", "yes");
    Sleep(ms);
    orc_kv("HELPER_COMPLETED", "yes");
    orc_kv("SURVIVED_SLEEP", "yes");
    orc_check("COMPLETED_AFTER_SLEEP", 1);
    return orc_end();
}
