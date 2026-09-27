/* Every byte value 0..255 on stdout exactly once, in order, with no newline
 * translation and an embedded NUL. The oracle lines go to stderr so stdout is
 * pure binary. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    unsigned char all[256];
    int i;
    setvbuf(stderr, NULL, _IOLBF, 0);
    for (i = 0; i < 256; i++) all[i] = (unsigned char)i;
    fprintf(stderr, "FIXTURE_ID=linux-io-binary-stdout\n");
    if (fwrite(all, 1, sizeof all, stdout) != sizeof all) {
        fprintf(stderr, "RESULT=FAIL\n");
        return 1;
    }
    fflush(stdout);
    fprintf(stderr, "BINARY_BYTES=256\n");
    fprintf(stderr, "BINARY_FNV1A=%016lx\n", orc_fnv1a(all, sizeof all));
    fprintf(stderr, "RESULT=PASS\n");
    return 0;
}
