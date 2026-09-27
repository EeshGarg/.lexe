/* stdout only. Nothing is written to stderr at all -- a consumer that merges the
 * streams cannot tell this apart from io_both, which is why they are separate. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    int i;
    orc_begin("linux-io-stdout-only");
    for (i = 1; i <= 10; i++) orc_kv("LINE", "%d", i);
    orc_kv("STDERR_BYTES_WRITTEN", "0");
    return orc_end();
}
