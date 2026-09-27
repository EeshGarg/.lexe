/* The bootstrap stage: the layer real launchers use to pick an executable,
 * unpack, or patch before handing over to the application proper. */
#include "t_common.h"

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "chain-wait";
    HANDLE child;
    orc_begin_fixed("t_bootstrap");
    orc_kv("NODE", "bootstrap");
    orc_kv("MODE", "%s", mode);
    orc_obs("PARENT_VISIBLE", "%s", "unknown-on-windows");
    orc_kv("WILL_WAIT_FOR_CHILD", "%s", tree_waits(mode, 1) ? "yes" : "no");
    child = tree_spawn(L"t_main.exe", mode, 0, "MAIN");
    orc_check("MAIN_STARTED", child != NULL);
    if (!child) return orc_end();
    if (tree_waits(mode, 1)) {
        DWORD code = tree_wait(child, "MAIN", 120000);
        orc_kv("MAIN_EXIT_SEEN", "%s", code != 0xFFFFFFFFu ? "yes" : "no");
        orc_kv("BOOTSTRAP_OUTLIVED_MAIN", "yes");
    } else {
        CloseHandle(child);
        orc_kv("BOOTSTRAP_OUTLIVED_MAIN", "no");
    }
    orc_kv("BOOTSTRAP_EXIT", "0");
    return orc_end();
}
