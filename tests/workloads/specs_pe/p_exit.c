/* Exits with the code in argv[1] after a complete oracle record. A non-zero exit
 * is the declared outcome, not a malfunction. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    int code = argc > 1 ? atoi(argv[1]) : 0;
    orc_begin("pe-outcome-exit");
    orc_kv("EXIT_CODE_INTENDED", "%d", code);
    orc_kv("WORK_DONE", "yes");
    orc_end();
    return code;
}
