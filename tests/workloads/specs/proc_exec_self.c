/* execve of its own image with a marker argument: the second incarnation is the
 * one that reports PASS, so a broken exec shows up as a missing PHASE=two. */
#include "oracle.h"
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
    orc_begin("linux-proc-exec-self");
    if (argc > 1 && strcmp(argv[1], "--phase-two") == 0) {
        orc_kv("PHASE", "two");
        orc_kv("ARGC", "%d", argc);
        return orc_end();
    }
    orc_kv("PHASE", "one");
    {
        char *av[3];
        av[0] = argv[0]; av[1] = (char *)"--phase-two"; av[2] = NULL;
        fflush(stdout);
        execve("/proc/self/exe", av, envp);
        orc_kv("EXEC_FAILED", "%s", orc_errno_name(errno));
        orc_check("EXEC_OK", 0);
    }
    return orc_end();
}
