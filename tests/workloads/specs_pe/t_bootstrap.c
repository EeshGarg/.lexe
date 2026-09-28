/* The bootstrap stage: the layer real launchers use to pick an executable,
 * unpack, or patch before handing over to the application proper.
 *
 * In the deep-* modes it hands over to t_stage2 rather than straight to t_main, so
 * the chain below it is two levels longer than the shape every other mode uses. */
#include "t_common.h"

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "chain-wait";
    const wchar_t *next = tree_is_deep(mode) ? L"t_stage2.exe" : L"t_main.exe";
    const char *label = tree_is_deep(mode) ? "STAGE2" : "MAIN";
    HANDLE child;
    orc_begin_fixed("t_bootstrap");
    orc_kv("NODE", "bootstrap");
    orc_kv("MODE", "%s", mode);
    orc_kv("LEVEL", "1");
    orc_kv("CHILD_NODE", "%s", tree_is_deep(mode) ? "stage2" : "main");
    tree_state_note("BOOTSTRAP");
    orc_obs("PARENT_VISIBLE", "%s", "unknown-on-windows");
    orc_kv("WILL_WAIT_FOR_CHILD", "%s", tree_waits(mode, 1) ? "yes" : "no");
    child = tree_spawn(next, mode, 0, label);
    orc_check(tree_is_deep(mode) ? "STAGE2_STARTED" : "MAIN_STARTED", child != NULL);
    if (!child) return orc_end();
    if (tree_waits(mode, 1)) {
        DWORD code = tree_wait(child, label, 120000);
        orc_kv("CHILD_EXIT_SEEN", "%s", code != 0xFFFFFFFFu ? "yes" : "no");
        if (!tree_is_deep(mode))
            orc_kv("MAIN_EXIT_SEEN", "%s", code != 0xFFFFFFFFu ? "yes" : "no");
        orc_kv("BOOTSTRAP_OUTLIVED_MAIN", "yes");
    } else {
        CloseHandle(child);
        orc_kv("BOOTSTRAP_OUTLIVED_MAIN", "no");
    }
    orc_kv("BOOTSTRAP_EXIT", "0");
    return orc_end();
}
