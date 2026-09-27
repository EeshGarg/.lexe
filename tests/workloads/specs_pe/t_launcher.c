/* The launcher: the top of the tree and the one that matters most, because in
 * real Windows software the launcher exiting immediately is the NORM, not the
 * exception. Whatever supervises this tree must not conclude from the launcher's
 * exit that the application has finished. */
#include "t_common.h"

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "chain-wait";
    HANDLE child;
    orc_begin_fixed("t_launcher");
    orc_kv("NODE", "launcher");
    orc_kv("MODE", "%s", mode);
    orc_kv("WILL_WAIT_FOR_CHILD", "%s", tree_waits(mode, 0) ? "yes" : "no");
    child = tree_spawn(L"t_bootstrap.exe", mode, 0, "BOOTSTRAP");
    orc_check("BOOTSTRAP_STARTED", child != NULL);
    if (!child) return orc_end();
    if (tree_waits(mode, 0)) {
        DWORD code = tree_wait(child, "BOOTSTRAP", 120000);
        orc_kv("BOOTSTRAP_EXIT_SEEN", "%s", code != 0xFFFFFFFFu ? "yes" : "no");
        orc_kv("LAUNCHER_OUTLIVED_TREE", "yes");
    } else {
        CloseHandle(child);
        orc_kv("LAUNCHER_OUTLIVED_TREE", "no");
        orc_kv("TREE_STILL_RUNNING_AT_LAUNCHER_EXIT", "yes");
    }
    orc_kv("LAUNCHER_EXIT", "0");
    return orc_end();
}
