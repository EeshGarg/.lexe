/* execve of a sibling binary (helper_child), replacing this image. The output of
 * the helper is the rest of the stdout of the specimen. */
#include "oracle.h"
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
    orc_begin("linux-proc-exec-helper");
    if (argc < 2) { orc_kv("USAGE", "proc_exec_helper <helper-path>"); return 2; }
    orc_kv("PHASE", "pre-exec");
    fflush(stdout);
    {
        char *av[4];
        av[0] = argv[1]; av[1] = (char *)"exec-target"; av[2] = (char *)"0"; av[3] = NULL;
        execve(argv[1], av, envp);
    }
    orc_kv("EXEC_FAILED", "%s", orc_errno_name(errno));
    orc_check("EXEC_OK", 0);
    return orc_end();
}
