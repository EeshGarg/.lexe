/* A SUPERVISOR: it starts the same worker over and over, waits for each one, and
 * records what each generation did.
 *
 * This is the shape of every crash-restart loop, every "keep the server up" wrapper
 * and every game launcher that relaunches its payload after a patch. What it makes
 * observable that nothing else in the family does:
 *
 *   - one process spawning several SEQUENTIAL children with the same image and the
 *     same name, so process creation is exercised repeatedly in one process rather
 *     than once;
 *   - each generation's exit status collected independently, so a layer that
 *     reports the FIRST child's status for every later one is caught;
 *   - a worker oracle file that each generation OVERWRITES, beside a supervisor log
 *     that ACCUMULATES. After the tree is gone, the log says three generations ran
 *     and the worker oracle describes only the last -- which is exactly the evidence
 *     problem a restart loop creates for anything watching from outside.
 */
#include "t_common.h"

#define GENERATIONS 3

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "supervisor-restart";
    int gen, completed = 0, all_33 = 1;
    FILE *log;
    orc_begin_fixed("t_supervisor");
    orc_kv("NODE", "supervisor");
    orc_kv("MODE", "%s", mode);
    tree_state_note("SUPERVISOR");
    orc_kv("RESTARTS_REQUESTED", "%d", GENERATIONS);

    log = fopen("supervisor.log", "w");
    for (gen = 0; gen < GENERATIONS; gen++) {
        char label[32];
        HANDLE child;
        DWORD code;
        snprintf(label, sizeof label, "GEN%d", gen);
        child = tree_spawn(L"t_worker.exe", mode, 0, label);
        if (!child) { all_33 = 0; break; }
        code = tree_wait(child, label, 60000);
        if (code != 33) all_33 = 0;
        completed++;
        if (log) {
            fprintf(log, "GEN=%d EXIT=%lu\n", gen, (unsigned long)code);
            fflush(log);
        }
    }
    if (log) {
        fprintf(log, "GENERATIONS=%d\n", completed);
        fclose(log);
    }
    orc_kv("GENERATIONS_COMPLETED", "%d", completed);
    orc_check("EVERY_GENERATION_STARTED_AND_WAS_REAPED", completed == GENERATIONS);
    orc_check("EVERY_GENERATION_EXITED_33", all_33 && completed == GENERATIONS);
    orc_check("WORKER_ORACLE_IS_FROM_THE_LAST_GENERATION_ONLY",
              tree_flag_present(L"t_worker.oracle"));
    orc_kv("SUPERVISOR_EXIT", "0");
    return orc_end();
}
