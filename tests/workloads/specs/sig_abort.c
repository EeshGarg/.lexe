/* abort(): SIGABRT with core disposition, after a deterministic stderr message,
 * so a consumer sees both the stream content and the abnormal termination. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    orc_begin("linux-outcome-abort");
    orc_kv("ABORT_REASON", "deliberate-invariant-violation");
    orc_ekv("STDERR_BEFORE_ABORT", "invariant x>0 failed");
    orc_expect_death("sigabrt");
    abort();
    return orc_end();
}
