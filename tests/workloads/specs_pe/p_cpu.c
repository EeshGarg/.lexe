/* A deterministic CPU-bound run: the checksum must be bit-identical natively,
 * under Wine and under Proton, and under every compiler. It is the control for
 * every other difference in the corpus. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    unsigned long long x = 0x243F6A8885A308D3ULL;
    unsigned long rounds = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000000UL, i;
    orc_begin("pe-run-cpu-bound");
    orc_kv("ROUNDS", "%lu", rounds);
    for (i = 0; i < rounds; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        x += i;
    }
    orc_kv("CHECKSUM", "%016llx", x);
    orc_check("WORK_COMPLETED", i == rounds);
    return orc_end();
}
