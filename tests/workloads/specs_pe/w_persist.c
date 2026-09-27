/* Persistent state in the working directory: appends one line per launch and
 * reports the count. Two consecutive launches must read 1 then 2, which is how a
 * consumer can tell whether state survived between launches. */
#include "oracle_win.h"

int main(void) {
    FILE *f;
    long lines = 0;
    int c;
    orc_begin("pe-fs-persistent-state");
    f = fopen("state.dat", "ab");
    orc_check("OPEN_APPEND", f != NULL);
    if (!f) return orc_end();
    fputs("run\n", f);
    orc_check("FLUSH", fflush(f) == 0);
    fclose(f);
    f = fopen("state.dat", "rb");
    if (f) {
        while ((c = fgetc(f)) != EOF) if (c == '\n') lines++;
        fclose(f);
    }
    orc_kv("RUN_COUNT", "%ld", lines);
    orc_check("AT_LEAST_ONE_RUN", lines >= 1);
    return orc_end();
}
