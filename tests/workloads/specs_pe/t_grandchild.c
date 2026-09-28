/* The deepest node: a child of the worker, which makes it a GRANDCHILD of the
 * application and a great-great-grandchild of the launcher.
 *
 * It sleeps for argv[2] milliseconds -- long enough that in the detached modes every
 * process above it is gone before it wakes -- and only then writes its completion
 * lines and its share of the tree's persistent state. Its oracle file is therefore
 * the evidence for the strongest claim in this family:
 *
 *   work five levels down survived the exit of everything that started it, and the
 *   state it wrote is still on disk after no process from the tree remains.
 *
 * It also looks for the flag its parent and its grandparent leave behind on the way
 * out, so "I outlived them" is a fact it checked rather than a fact inferred from
 * timing.
 */
#include "t_common.h"

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "deep-chain";
    DWORD ms = argc > 2 ? (DWORD)strtoul(argv[2], NULL, 10) : 300;
    orc_begin_fixed("t_grandchild");
    orc_kv("NODE", "grandchild");
    orc_kv("MODE", "%s", mode);
    orc_kv("DEPTH", "5");
    orc_kv("SLEEP_MS", "%lu", (unsigned long)ms);
    orc_kv("GRANDCHILD_STARTED", "yes");
    orc_kv("PARENT_GONE_AT_START", "%s",
           tree_flag_present(L"worker_exited.flag") ? "yes" : "no");
    Sleep(ms);
    orc_kv("PARENT_GONE_AFTER_SLEEP", "%s",
           tree_flag_present(L"worker_exited.flag") ? "yes" : "no");
    orc_kv("GRANDPARENT_GONE_AFTER_SLEEP", "%s",
           tree_flag_present(L"main_exited.flag") ? "yes" : "no");
    tree_state_note("GRANDCHILD");
    orc_kv("GRANDCHILD_COMPLETED", "yes");
    orc_kv("WROTE_STATE_AFTER_SLEEP", "yes");
    orc_check("COMPLETED_AFTER_SLEEP", 1);
    orc_end();
    /* A status of its own, so the waiting modes have something specific to carry
     * back up five levels. */
    return 44;
}
