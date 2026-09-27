/* atexit and stdio flush ordering: three handlers must run in reverse
 * registration order, after main returns, and their output must still reach the
 * captured stdout. */
#include "oracle.h"
#include <unistd.h>

static void h1(void) { printf("ATEXIT=1\n"); }
static void h2(void) { printf("ATEXIT=2\n"); }
static void h3(void) { printf("ATEXIT=3\n"); }

int main(void) {
    orc_begin("linux-outcome-atexit-order");
    orc_check("REG1", atexit(h1) == 0);
    orc_check("REG2", atexit(h2) == 0);
    orc_check("REG3", atexit(h3) == 0);
    orc_kv("EXPECTED_ORDER", "3,2,1");
    orc_end();
    return 7;
}
