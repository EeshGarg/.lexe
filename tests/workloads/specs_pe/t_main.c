/* The application proper. What it does with its own children is the mode:
 *
 *   fanout             start helper, worker and crash handler, wait for all three
 *   crash-child        start the crash handler alone and report its abnormal status
 *   no-wait-crash      start the crash handler and NEVER wait: the crash is invisible
 *                      to every process above this one
 *   crash-at-depth     the worker starts the crash handler; this node waits only for
 *                      the worker and sees a clean, specific 33
 *   wait-timeout       start a slow helper and give up on it after 500 ms
 *   detach-helper      start the helper DETACHED and exit at once, leaving it running
 *   orphan-tree        same, with every parent above also exiting immediately
 *   supervisor-restart hand over to a supervisor that restarts the worker three times
 *   redirect-to-file   give the worker a FILE as both its standard handles
 *   split-stdio        give the worker a file for stdout and INHERIT stderr to it
 *   gui-leaf           start the window node DETACHED and exit, leaving a window up
 *                      with no live ancestor
 *   gui-top            the window belongs to the launcher; this node just works
 *   deep-chain         wait for the worker, which waits for a grandchild
 *   deep-orphan        start the worker and exit at once, five levels of nobody waiting
 *   anything else      start the worker and wait for it
 *
 * On the way out it drops main_exited.flag, so a node that outlives it can PROVE
 * that rather than infer it from a sleep.
 */
#include "t_common.h"

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "chain-wait";
    orc_begin_fixed("t_main");
    orc_kv("NODE", "main");
    orc_kv("MODE", "%s", mode);
    orc_kv("LEVEL", "%s", tree_is_deep(mode) ? "3" : "2");
    tree_state_note("MAIN");

    if (strcmp(mode, "fanout") == 0) {
        HANDLE helper = tree_spawn(L"t_helper.exe", "300", 0, "HELPER");
        HANDLE worker = tree_spawn(L"t_worker.exe", mode, 0, "WORKER");
        HANDLE crash  = tree_spawn(L"t_crash_handler.exe", mode, 0, "CRASH");
        orc_kv("CHILDREN_STARTED", "%d",
               (helper ? 1 : 0) + (worker ? 1 : 0) + (crash ? 1 : 0));
        DWORD hc = 0xFFFFFFFFu, wc = 0xFFFFFFFFu, cc = 0xFFFFFFFFu;
        if (helper) hc = tree_wait(helper, "HELPER", 60000);
        if (worker) wc = tree_wait(worker, "WORKER", 60000);
        if (crash)  cc = tree_wait(crash,  "CRASH",  60000);
        orc_check("ALL_THREE_STARTED", helper && worker && crash);
        orc_check("HELPER_REAPED_CLEAN", hc == 0);
        orc_check("WORKER_REAPED_33", wc == 33);
        orc_check("CRASH_CHILD_REAPED", cc != 0xFFFFFFFFu);
        orc_kv("MAIN_WAITED_FOR_ALL", "yes");
        orc_kv("PARENT_SURVIVED_CHILD_CRASH", "yes");
    } else if (strcmp(mode, "crash-child") == 0) {
        HANDLE crash = tree_spawn(L"t_crash_handler.exe", mode, 0, "CRASH");
        orc_check("CRASH_CHILD_STARTED", crash != NULL);
        if (crash) {
            DWORD code = tree_wait(crash, "CRASH", 120000);
            orc_kv("PARENT_SURVIVED_CHILD_CRASH", "yes");
            orc_kv("CHILD_STATUS_WAS_NONZERO", "%s", code != 0 ? "yes" : "no");
        }
    } else if (strcmp(mode, "no-wait-crash") == 0) {
        /* The crash happens; this node never asks about it and exits 0. Nothing
         * above it has any way to find out, which is the point. */
        HANDLE crash = tree_spawn(L"t_crash_handler.exe", mode, 0, "CRASH");
        orc_check("CRASH_CHILD_STARTED", crash != NULL);
        if (crash) CloseHandle(crash);
        orc_kv("MAIN_WAITED_FOR_CRASH_CHILD", "no");
        orc_kv("MAIN_NOTICED_THE_CRASH", "no");
        orc_kv("MAIN_EXIT_STATUS_IS_CLEAN_ANYWAY", "yes");
        /* Give the child time to reach its fault while this node is still alive,
         * so the crash is not merely a child killed by its parent going away. */
        Sleep(400);
        orc_kv("CRASH_EVIDENCE_IS_ONLY_IN_THE_CHILDS_ORACLE", "yes");
    } else if (strcmp(mode, "wait-timeout") == 0) {
        HANDLE helper = tree_spawn(L"t_helper.exe", "4000", 0, "HELPER");
        orc_check("SLOW_HELPER_STARTED", helper != NULL);
        if (helper) {
            /* tree_wait reports WAIT_TIMEOUT as HELPER_WAIT=timeout and does NOT
             * kill the child: it keeps running with nobody waiting for it. */
            tree_wait(helper, "HELPER", 500);
            orc_kv("MAIN_GAVE_UP_WAITING", "yes");
            orc_kv("MAIN_WAIT_TIMEOUT_MS", "500");
            orc_kv("HELPER_LEFT_RUNNING", "yes");
            orc_kv("MAIN_EXITS_FIRST", "yes");
        }
    } else if (strcmp(mode, "supervisor-restart") == 0) {
        HANDLE sup = tree_spawn(L"t_supervisor.exe", mode, 0, "SUPERVISOR");
        orc_check("SUPERVISOR_STARTED", sup != NULL);
        if (sup) {
            DWORD code = tree_wait(sup, "SUPERVISOR", 120000);
            orc_check("SUPERVISOR_EXITED_CLEAN", code == 0);
        }
    } else if (strcmp(mode, "redirect-to-file") == 0) {
        HANDLE f = tree_inheritable_file(L"worker_redirected.txt");
        orc_check("REDIRECT_TARGET_OPENED", f != INVALID_HANDLE_VALUE);
        if (f != INVALID_HANDLE_VALUE) {
            HANDLE worker = tree_spawn_redirected(L"t_worker.exe", mode, f, f, "WORKER");
            orc_check("WORKER_STARTED", worker != NULL);
            if (worker) {
                DWORD code = tree_wait(worker, "WORKER", 60000);
                orc_check("WORKER_EXIT_33", code == 33);
            }
            CloseHandle(f);   /* must close before the content is readable */
            orc_check("WORKER_STDOUT_LANDED_IN_THE_FILE",
                      tree_file_contains(L"worker_redirected.txt", "NODE=worker"));
            orc_check("WORKER_STDERR_LANDED_IN_THE_SAME_FILE",
                      tree_file_contains(L"worker_redirected.txt", "WORKER_STDERR_MARKER=yes"));
            orc_kv("BOTH_STREAMS_WENT_TO_ONE_FILE", "yes");
        }
    } else if (strcmp(mode, "split-stdio") == 0) {
        /* One stream redirected, the other INHERITED. The worker's stderr goes
         * wherever this node's stderr goes -- out of the tree entirely, to whoever
         * launched it -- while its stdout lands in a file this node can read. */
        HANDLE f = tree_inheritable_file(L"worker_split_stdout.txt");
        orc_check("SPLIT_TARGET_OPENED", f != INVALID_HANDLE_VALUE);
        if (f != INVALID_HANDLE_VALUE) {
            HANDLE worker = tree_spawn_redirected(L"t_worker.exe", mode, f, NULL, "WORKER");
            orc_check("WORKER_STARTED", worker != NULL);
            if (worker) {
                DWORD code = tree_wait(worker, "WORKER", 60000);
                orc_check("WORKER_EXIT_33", code == 33);
            }
            CloseHandle(f);
            orc_check("REDIRECTED_STDOUT_LANDED_IN_THE_FILE",
                      tree_file_contains(L"worker_split_stdout.txt", "NODE=worker"));
            orc_check("INHERITED_STDERR_DID_NOT_LAND_IN_THE_FILE",
                      !tree_file_contains(L"worker_split_stdout.txt",
                                          "WORKER_STDERR_MARKER=yes"));
            orc_kv("SPLIT_STDOUT_TO_FILE", "yes");
            orc_kv("SPLIT_STDERR_INHERITED", "yes");
        }
    } else if (strcmp(mode, "gui-leaf") == 0) {
        HANDLE window = tree_spawn_args(L"t_window.exe", "gui-leaf 2500", 1, "WINDOW");
        orc_check("DETACHED_WINDOW_STARTED", window != NULL);
        if (window) CloseHandle(window);
        orc_kv("MAIN_WAITED_FOR_WINDOW", "no");
        orc_kv("WINDOW_OWNER_LEFT_RUNNING", "yes");
        orc_kv("MAIN_EXITS_FIRST", "yes");
    } else if (strcmp(mode, "gui-top") == 0) {
        /* The window belongs to the launcher in this mode; here there is only work,
         * and the worker is what eventually brings the window down. */
        HANDLE worker = tree_spawn(L"t_worker.exe", mode, 0, "WORKER");
        orc_check("WORKER_STARTED", worker != NULL);
        if (worker) {
            DWORD code = tree_wait(worker, "WORKER", 120000);
            orc_check("WORKER_EXIT_33", code == 33);
        }
        orc_kv("WINDOW_IS_NOT_OWNED_BY_THIS_NODE", "yes");
    } else if (strcmp(mode, "detach-helper") == 0 || strcmp(mode, "orphan-tree") == 0) {
        HANDLE helper = tree_spawn(L"t_helper.exe", "1500", 1, "HELPER");
        orc_check("DETACHED_HELPER_STARTED", helper != NULL);
        if (helper) CloseHandle(helper);
        orc_kv("MAIN_WAITED_FOR_HELPER", "no");
        orc_kv("HELPER_LEFT_RUNNING", "yes");
        orc_kv("MAIN_EXITS_FIRST", "yes");
    } else if (strcmp(mode, "deep-orphan") == 0) {
        /* Five levels and not one wait anywhere. */
        HANDLE worker = tree_spawn(L"t_worker.exe", mode, 0, "WORKER");
        orc_check("WORKER_STARTED", worker != NULL);
        if (worker) CloseHandle(worker);
        orc_kv("MAIN_WAITED_FOR_WORKER", "no");
        orc_kv("MAIN_EXITS_FIRST", "yes");
    } else {
        HANDLE worker = tree_spawn(L"t_worker.exe", mode, 0, "WORKER");
        orc_check("WORKER_STARTED", worker != NULL);
        if (worker) {
            DWORD code = tree_wait(worker, "WORKER", 120000);
            orc_check("WORKER_EXIT_33", code == 33);
        }
    }
    orc_kv("MAIN_EXIT", "0");
    orc_end();
    tree_flag(L"main_exited.flag");
    return 0;
}
