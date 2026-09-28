/* A worker that does deterministic work and exits 33, so its parent has a
 * specific non-zero status to observe and report.
 *
 * It is also the node with children of its own in the deep modes, which is what
 * makes the tree six levels rather than three:
 *
 *   deep-chain          spawn t_grandchild and WAIT for it, carrying its status up
 *   deep-orphan         spawn t_grandchild and exit at once
 *   grandchild-survives spawn t_grandchild DETACHED with a long sleep, so it
 *                       outlives this node AND this node's parent
 *   crash-at-depth      spawn the crash handler and never wait: the crash is four
 *                       levels down and nothing above level 3 ever hears about it
 *
 * It writes one line to STDERR as well as to stdout, which is how the redirect
 * modes tell the two streams apart, and it drops tree_done.flag on the way out,
 * which is what brings the launcher's window down in gui-top.
 */
#include "t_common.h"

int main(int argc, char **argv) {
    unsigned long long x = 0x243F6A8885A308D3ULL;
    const char *mode = argc > 1 ? argv[1] : "chain-wait";
    int i;
    HANDLE child = NULL;
    orc_begin_fixed("t_worker");
    orc_kv("NODE", "worker");
    orc_kv("MODE", "%s", mode);
    orc_kv("LEVEL", "%s", tree_is_deep(mode) ? "4" : "3");
    tree_state_note("WORKER");
    /* One line on the OTHER stream, so a redirect that captures only one of them
     * is visible as a difference rather than as an absence. */
    orc_ekv("WORKER_STDERR_MARKER", "yes");

    if (strcmp(mode, "deep-chain") == 0) {
        child = tree_spawn_args(L"t_grandchild.exe", "deep-chain 300", 0, "GRANDCHILD");
        orc_check("GRANDCHILD_STARTED", child != NULL);
        if (child) {
            DWORD code = tree_wait(child, "GRANDCHILD", 60000);
            orc_check("GRANDCHILD_EXIT_44", code == 44);
            orc_kv("WORKER_WAITED_FOR_GRANDCHILD", "yes");
            orc_kv("WORKER_OUTLIVED_GRANDCHILD", "yes");
        }
    } else if (strcmp(mode, "deep-orphan") == 0) {
        child = tree_spawn_args(L"t_grandchild.exe", "deep-orphan 2500", 1, "GRANDCHILD");
        orc_check("GRANDCHILD_STARTED", child != NULL);
        if (child) CloseHandle(child);
        orc_kv("WORKER_WAITED_FOR_GRANDCHILD", "no");
        orc_kv("GRANDCHILD_LEFT_RUNNING", "yes");
    } else if (strcmp(mode, "grandchild-survives") == 0) {
        child = tree_spawn_args(L"t_grandchild.exe", "grandchild-survives 2500", 1,
                                "GRANDCHILD");
        orc_check("GRANDCHILD_STARTED", child != NULL);
        if (child) CloseHandle(child);
        orc_kv("WORKER_WAITED_FOR_GRANDCHILD", "no");
        orc_kv("GRANDCHILD_LEFT_RUNNING", "yes");
        orc_kv("GRANDCHILD_WILL_OUTLIVE_ITS_GRANDPARENT", "yes");
    } else if (strcmp(mode, "crash-at-depth") == 0) {
        child = tree_spawn(L"t_crash_handler.exe", mode, 0, "CRASH");
        orc_check("CRASH_CHILD_STARTED", child != NULL);
        if (child) CloseHandle(child);
        orc_kv("WORKER_WAITED_FOR_CRASH_CHILD", "no");
        orc_kv("WORKER_REPORTS_ITS_OWN_CLEAN_STATUS_ANYWAY", "yes");
        Sleep(400);   /* let the crash happen while this node is still alive */
    }

    for (i = 0; i < 2000000; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x += (unsigned)i; }
    orc_kv("WORK_CHECKSUM", "%016llx", x);
    orc_kv("WORKER_EXIT_INTENT", "33");
    orc_check("WORK_DONE", 1);
    orc_end();
    tree_flag(L"tree_done.flag");
    tree_flag(L"worker_exited.flag");
    return 33;
}
