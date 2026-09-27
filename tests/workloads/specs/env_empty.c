/* Re-executes itself with an empty environment and reports, in phase two, that
 * environ really is empty. A program that deliberately destroys its own context. */
#include "oracle.h"
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    int count = 0;
    while (environ[count]) count++;
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1 && strcmp(argv[1], "--phase-two") == 0) {
        printf("PHASE=two\n");
        printf("ENVIRON_COUNT=%d\n", count);
        printf("ENVIRON_EMPTY=%s\n", count == 0 ? "yes" : "no");
        printf("GETENV_PATH_PRESENT=%s\n", getenv("PATH") ? "yes" : "no");
        printf("RESULT=%s\n", count == 0 ? "PASS" : "FAIL");
        fflush(stdout);
        return count == 0 ? 0 : 1;
    }
    printf("FIXTURE_ID=linux-env-emptied\n");
    printf("PHASE=one\n");
    fflush(stdout);
    {
        char *av[3];
        char *ev[1];
        av[0] = argv[0]; av[1] = (char *)"--phase-two"; av[2] = NULL;
        ev[0] = NULL;
        execve("/proc/self/exe", av, ev);
    }
    printf("EXEC_FAILED=%s\nRESULT=FAIL\n", orc_errno_name(errno));
    return 1;
}
