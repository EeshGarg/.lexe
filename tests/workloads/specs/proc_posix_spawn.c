/* posix_spawn rather than fork plus exec: a different kernel path to the same
 * observable outcome. */
#include "oracle.h"
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    pid_t p = 0;
    int st = 0, rc;
    char *av[4];
    orc_begin("linux-proc-posix-spawn");
    if (argc < 2) { orc_kv("USAGE", "proc_posix_spawn <helper-path>"); return 2; }
    av[0] = argv[1]; av[1] = (char *)"spawned"; av[2] = (char *)"31"; av[3] = NULL;
    fflush(stdout);
    rc = posix_spawn(&p, argv[1], NULL, NULL, av, environ);
    orc_kv("SPAWN_RC", "%d", rc);
    orc_check("SPAWN_OK", rc == 0);
    if (rc != 0) return orc_end();
    waitpid(p, &st, 0);
    orc_kv("CHILD_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_check("CHILD_EXIT_31", WIFEXITED(st) && WEXITSTATUS(st) == 31);
    return orc_end();
}
