/* stderr only: the oracle output itself is on fd 2 and stdout stays empty.
 * ORACLE_STREAM=stderr in the manifest tells the consumer where to look. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    int i;
    setvbuf(stderr, NULL, _IOLBF, 0);
    fprintf(stderr, "FIXTURE_ID=linux-io-stderr-only\n");
    for (i = 1; i <= 10; i++) fprintf(stderr, "LINE=%d\n", i);
    fprintf(stderr, "STDOUT_BYTES_WRITTEN=0\n");
    fprintf(stderr, "RESULT=PASS\n");
    fflush(stderr);
    return 0;
}
