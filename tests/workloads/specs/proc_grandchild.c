/* Three generations. Each writes a marker file in the working directory, and
 * the eldest verifies all three markers exist before exiting. */
#include "oracle.h"
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

static int touch(const char *name) {
    FILE *f = fopen(name, "w");
    if (!f) return 0;
    fprintf(f, "%s\n", name);
    fclose(f);
    return 1;
}

int main(void) {
    pid_t c;
    int st = 0;
    orc_begin("linux-proc-grandchild");
    c = fork();
    if (c == 0) {
        pid_t g = fork();
        if (g == 0) { touch("gen3.marker"); _exit(3); }
        {
            int s2 = 0;
            waitpid(g, &s2, 0);
            touch("gen2.marker");
            _exit(WIFEXITED(s2) ? WEXITSTATUS(s2) + 10 : 99);
        }
    }
    waitpid(c, &st, 0);
    touch("gen1.marker");
    orc_kv("CHILD_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_check("GEN3_MARKER", access("gen3.marker", F_OK) == 0);
    orc_check("GEN2_MARKER", access("gen2.marker", F_OK) == 0);
    orc_check("GEN1_MARKER", access("gen1.marker", F_OK) == 0);
    return orc_end();
}
