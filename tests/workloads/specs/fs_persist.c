/* Persistent state in the working directory: appends one line per run to
 * state.dat and reports the run count. Two consecutive runs must see 1 then 2,
 * which is how a consumer can tell whether state survived between launches. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    FILE *f;
    long lines = 0;
    int c;
    orc_begin("linux-fs-persistent-state");
    f = fopen("state.dat", "a");
    orc_check("OPEN_APPEND", f != NULL);
    if (!f) { orc_kv("OPEN_ERRNO", "%s", orc_errno_name(errno)); return orc_end(); }
    fprintf(f, "run\n");
    orc_check("FLUSH_OK", fflush(f) == 0);
    fclose(f);
    f = fopen("state.dat", "r");
    orc_check("OPEN_READ", f != NULL);
    if (f) {
        while ((c = fgetc(f)) != EOF) if (c == 10) lines++;
        fclose(f);
    }
    orc_kv("RUN_COUNT", "%ld", lines);
    orc_check("AT_LEAST_ONE_RUN", lines >= 1);
    return orc_end();
}
