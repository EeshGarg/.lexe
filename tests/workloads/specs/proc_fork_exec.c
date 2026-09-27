/* fork then exec the helper in the child; parent waits and reports the status.
 * The helper inherits stdout, so both appear in one capture. */
#include "oracle.h"
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    pid_t p;
    int st = 0;
    orc_begin("linux-proc-fork-exec");
    if (argc < 2) { orc_kv("USAGE", "proc_fork_exec <helper-path>"); return 2; }
    fflush(stdout);
    p = fork();
    if (p == 0) {
        char *av[4];
        av[0] = argv[1]; av[1] = (char *)"forked"; av[2] = (char *)"23"; av[3] = NULL;
        execv(argv[1], av);
        _exit(126);
    }
    orc_check("FORK_OK", p > 0);
    waitpid(p, &st, 0);
    orc_kv("CHILD_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_check("EXEC_IN_CHILD_OK", WIFEXITED(st) && WEXITSTATUS(st) == 23);
    return orc_end();
}
