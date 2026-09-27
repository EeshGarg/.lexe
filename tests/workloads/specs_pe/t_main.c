/* The application proper. What it does with its own children is the mode:
 *
 *   fanout        start helper, worker and crash handler, wait for all three
 *   crash-child   start the crash handler alone and report its abnormal status
 *   detach-helper start the helper DETACHED and exit at once, leaving it running
 *   orphan-tree   same, with every parent above also exiting immediately
 *   anything else start the worker and wait for it
 */
#include "t_common.h"

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "chain-wait";
    orc_begin_fixed("t_main");
    orc_kv("NODE", "main");
    orc_kv("MODE", "%s", mode);

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
    } else if (strcmp(mode, "detach-helper") == 0 || strcmp(mode, "orphan-tree") == 0) {
        HANDLE helper = tree_spawn(L"t_helper.exe", "1500", 1, "HELPER");
        orc_check("DETACHED_HELPER_STARTED", helper != NULL);
        if (helper) CloseHandle(helper);
        orc_kv("MAIN_WAITED_FOR_HELPER", "no");
        orc_kv("HELPER_LEFT_RUNNING", "yes");
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
    return orc_end();
}
