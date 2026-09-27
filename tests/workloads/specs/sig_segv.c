/* A deliberate SIGSEGV: a write through a null pointer the compiler cannot
 * reason away, because the pointer arrives through a volatile global. */
#include "oracle.h"
#include <unistd.h>

static volatile int *volatile target = 0;

int main(void) {
    orc_begin("linux-outcome-sigsegv");
    orc_kv("FAULT_KIND", "null-write");
    orc_expect_death("sigsegv");
    *target = 1;
    orc_kv("UNREACHABLE", "yes");
    orc_check("CRASHED", 0);
    return orc_end();
}
