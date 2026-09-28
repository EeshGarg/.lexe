/* An EXTRA chain level, used only by the deep-* modes, which exists so the family
 * has a shape deeper than three.
 *
 *     launcher -> bootstrap -> stage2 -> main -> worker -> grandchild
 *
 * Real installers and launchers stack up exactly like this -- a bootstrapper that
 * unpacks a second bootstrapper that starts a service host that starts the game --
 * and every level added is another place a supervisor's parent-pid bookkeeping can
 * lose track of what it is watching.
 */
#include "t_common.h"

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "deep-chain";
    HANDLE child;
    orc_begin_fixed("t_stage2");
    orc_kv("NODE", "stage2");
    orc_kv("MODE", "%s", mode);
    orc_kv("LEVEL", "2");
    tree_state_note("STAGE2");
    orc_kv("WILL_WAIT_FOR_CHILD", "%s", tree_waits(mode, 2) ? "yes" : "no");
    child = tree_spawn(L"t_main.exe", mode, 0, "MAIN");
    orc_check("MAIN_STARTED", child != NULL);
    if (!child) return orc_end();
    if (tree_waits(mode, 2)) {
        DWORD code = tree_wait(child, "MAIN", 120000);
        orc_kv("MAIN_EXIT_SEEN", "%s", code != 0xFFFFFFFFu ? "yes" : "no");
        orc_kv("STAGE2_OUTLIVED_MAIN", "yes");
    } else {
        CloseHandle(child);
        orc_kv("STAGE2_OUTLIVED_MAIN", "no");
    }
    orc_kv("STAGE2_EXIT", "0");
    return orc_end();
}
