/* A large memory image that costs nothing on disk.
 *
 * linux-format-large-binary carries 48 MiB of initialised .data, so the file on
 * disk is 48 MiB and every page has to be read. This is the opposite shape and a
 * genuinely different one: 256 MiB of .bss, which occupies no space in the file
 * at all. The binary stays small, `ls -l` says nothing is going on, and the
 * process still needs a quarter of a gigabyte of zeroed anonymous memory the
 * moment it is loaded.
 *
 * Anything that sizes a program by its file size is wrong about this program by
 * three orders of magnitude, and the two specimens together are what make that
 * measurable rather than assertable.
 *
 * The array is touched sparsely -- one byte per 1 MiB -- and checksummed, so the
 * pages must genuinely arrive and be zero, while the resident cost stays small
 * enough that the specimen is cheap to run. The kernel's promise that .bss reads
 * as zero is the thing being checked.
 */
#include "oracle.h"

#include <unistd.h>

#define BSS_BYTES (256u * 1024u * 1024u)
#define STRIDE    (1u * 1024u * 1024u)

/* Uninitialised at file scope: .bss, not .data. */
static unsigned char big[BSS_BYTES];

int main(void) {
    unsigned long i, touched = 0, nonzero = 0;
    unsigned long sum = 0;

    orc_begin("linux-format-large-bss");
    orc_kv("BSS_BYTES", "%u", BSS_BYTES);
    orc_kv("STRIDE_BYTES", "%u", STRIDE);

    /* Read first: .bss must already be zero before anything writes to it. */
    for (i = 0; i < BSS_BYTES; i += STRIDE) {
        if (big[i] != 0) nonzero++;
        touched++;
    }
    orc_kv("PAGES_PROBED", "%lu", touched);
    orc_check("BSS_READS_AS_ZERO", nonzero == 0);

    /* Now write a value that is a pure function of the offset and read it back,
     * so the pages are demonstrably real and distinct rather than one shared
     * zero page the kernel handed out for every read. */
    for (i = 0; i < BSS_BYTES; i += STRIDE)
        big[i] = (unsigned char)((i / STRIDE) & 0xFF);
    for (i = 0; i < BSS_BYTES; i += STRIDE)
        sum += big[i];
    orc_kv("WRITEBACK_SUM", "%lu", sum);
    orc_check("PAGES_ARE_DISTINCT", sum == 32640ul);   /* 0+1+...+255 */

    orc_obs("SELF_EXE_SIZE_IS_NOT_THE_MEMORY_SIZE", "see binary.size_bytes");
    return orc_end();
}
