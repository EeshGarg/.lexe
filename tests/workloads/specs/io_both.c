/* Both streams. Deterministic within each stream; captured merged, the relative
 * order is not guaranteed and must not be asserted. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    int i;
    orc_begin("linux-io-both-streams");
    orc_ekv("FIXTURE_ID", "linux-io-both-streams");
    for (i = 1; i <= 8; i++) {
        orc_kv("OUT_LINE", "%d", i);
        orc_ekv("ERR_LINE", "%d", i);
    }
    orc_ekv("ERR_TOTAL", "8");
    orc_kv("OUT_TOTAL", "8");
    orc_ekv("RESULT", "PASS");
    return orc_end();
}
