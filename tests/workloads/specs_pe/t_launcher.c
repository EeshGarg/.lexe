/* The launcher: the top of the tree and the one that matters most, because in
 * real Windows software the launcher exiting immediately is the NORM, not the
 * exception. Whatever supervises this tree must not conclude from the launcher's
 * exit that the application has finished.
 *
 * In the `gui-top` mode it also owns the WINDOW -- it starts t_window.exe as a
 * SIBLING of the payload chain and waits for both. That is the splash-screen shape:
 * the thing on the screen belongs to the launcher, and the work belongs to
 * processes several levels below it that the window knows nothing about.
 */
#include "t_common.h"

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "chain-wait";
    HANDLE child, window = NULL;
    orc_begin_fixed("t_launcher");
    orc_kv("NODE", "launcher");
    orc_kv("MODE", "%s", mode);
    orc_kv("LEVEL", "0");
    tree_state_note("LAUNCHER");
    orc_kv("WILL_WAIT_FOR_CHILD", "%s", tree_waits(mode, 0) ? "yes" : "no");

    if (strcmp(mode, "gui-top") == 0) {
        /* The window goes up BEFORE the payload chain is started, exactly as a
         * splash screen does, and it is a child of the launcher rather than of
         * anything in the chain. */
        window = tree_spawn_args(L"t_window.exe", "gui-top 8000", 0, "WINDOW_CHILD");
        orc_check("WINDOW_CHILD_STARTED", window != NULL);
        orc_kv("LAUNCHER_OWNED_THE_WINDOW_CHILD", "yes");
    }

    child = tree_spawn(L"t_bootstrap.exe", mode, 0, "BOOTSTRAP");
    orc_check("BOOTSTRAP_STARTED", child != NULL);
    if (!child) {
        if (window) CloseHandle(window);
        tree_flag(L"launcher_exited.flag");
        return orc_end();
    }
    if (tree_waits(mode, 0)) {
        DWORD code = tree_wait(child, "BOOTSTRAP", 120000);
        orc_kv("BOOTSTRAP_EXIT_SEEN", "%s", code != 0xFFFFFFFFu ? "yes" : "no");
        orc_kv("LAUNCHER_OUTLIVED_TREE", "yes");
    } else {
        CloseHandle(child);
        orc_kv("LAUNCHER_OUTLIVED_TREE", "no");
        orc_kv("TREE_STILL_RUNNING_AT_LAUNCHER_EXIT", "yes");
    }
    if (window) {
        /* The launcher outlives its own window child on purpose here: it is the
         * last thing in the tree to go, which is the opposite of gui-leaf. */
        DWORD wcode = tree_wait(window, "WINDOW_CHILD", 120000);
        orc_kv("WINDOW_CHILD_EXIT_SEEN", "%s", wcode != 0xFFFFFFFFu ? "yes" : "no");
        orc_kv("LAUNCHER_OUTLIVED_ITS_WINDOW", "yes");
    }
    if (strcmp(mode, "gui-leaf") == 0) {
        /* The launcher holds the door open while the detached window node finishes.
         *
         * NOT because the shape needs it -- everything that STARTED the window node
         * is already gone by this point, which is the property the mode exists to
         * show -- but because a GUI specimen runs inside a private, namespaced X
         * server, and when the process the wrapper launched returns, that namespace
         * and its display go away and take any surviving process with them. Waiting
         * on the window node's own flag file keeps the display alive long enough
         * for the window to live its full life, WITHOUT the launcher ever waiting on
         * a process handle: it never knew the window node's handle to begin with.
         * The evidence that the window outlived its starters is t_window.oracle,
         * not this wait. */
        /* The bound is deliberately far larger than the 2.5 s the window node
         * holds for. It is a backstop against a wedged window node, not a
         * timing expectation -- and a bound that was merely comfortable on an
         * idle machine turned into a failure on a busy one, which is how it came
         * to be this size. */
        int spins = 0;
        orc_kv("LAUNCHER_HELD_THE_DISPLAY_OPEN", "yes");
        orc_kv("LAUNCHER_WAITED_ON_A_PROCESS_HANDLE_FOR_THE_WINDOW", "no");
        while (!tree_flag_present(L"window_done.flag") && spins++ < 9600) Sleep(25);
        orc_kv("WINDOW_DONE_FLAG_SEEN", "%s",
               tree_flag_present(L"window_done.flag") ? "yes" : "no");
    }
    orc_kv("LAUNCHER_EXIT", "0");
    tree_flag(L"launcher_exited.flag");
    return orc_end();
}
