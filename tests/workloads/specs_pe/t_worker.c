/* A worker that does deterministic work and exits 33, so its parent has a
 * specific non-zero status to observe and report. */
#include "t_common.h"

int main(int argc, char **argv) {
    unsigned long long x = 0x243F6A8885A308D3ULL;
    int i;
    (void)argc; (void)argv;
    orc_begin_fixed("t_worker");
    orc_kv("NODE", "worker");
    for (i = 0; i < 2000000; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x += (unsigned)i; }
    orc_kv("WORK_CHECKSUM", "%016llx", x);
    orc_kv("WORKER_EXIT_INTENT", "33");
    orc_check("WORK_DONE", 1);
    orc_end();
    return 33;
}
