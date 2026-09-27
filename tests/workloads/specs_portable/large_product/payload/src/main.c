/* A portable recipe whose PRODUCT is large: 96 MiB of initialised data in the
 * built executable, checksummed at run time so the pages have to actually
 * arrive.
 *
 * The package itself is a few kilobytes of source. That asymmetry is the point:
 * nothing about the shipped package says how big the installed artifact will
 * be, and a size estimate taken from the payload is wrong by four orders of
 * magnitude. Anything that budgets disk, hashes the product, copies it between
 * directories or checks its integrity at every launch meets 96 MiB it did not
 * expect.
 *
 * The array is initialised with a non-zero element so the linker cannot put it
 * in .bss, which is the difference between a 96 MiB file and a 16 KiB one. That
 * single `= { 1 }` is load-bearing.
 */
#include <stdio.h>
#include <stdlib.h>

#define BLOB_BYTES (96u * 1024u * 1024u)

static unsigned char blob[BLOB_BYTES] = { 1 };

int main(void) {
    const char *id = getenv("FIXTURE_ID");
    unsigned long h = 14695981039346656037UL;
    unsigned int i;
    printf("FIXTURE_ID=%s\n", id ? id : "portable-large-product");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("BLOB_BYTES=%u\n", BLOB_BYTES);
    for (i = 0; i < BLOB_BYTES; i++) blob[i] = (unsigned char)((i * 31u + 7u) & 0xff);
    for (i = 0; i < BLOB_BYTES; i++) { h ^= blob[i]; h *= 1099511628211UL; }
    printf("BLOB_FNV1A=%016lx\n", h);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("BLOB_FIRST=%s\n", blob[0] == 7 ? "yes" : "no");
    printf("BLOB_LAST=%s\n",
           blob[BLOB_BYTES - 1] == (unsigned char)(((BLOB_BYTES - 1) * 31u + 7u) & 0xff)
           ? "yes" : "no");
    printf("RESULT=%s\n",
           (blob[0] == 7
            && blob[BLOB_BYTES - 1] == (unsigned char)(((BLOB_BYTES - 1) * 31u + 7u) & 0xff))
           ? "PASS" : "FAIL");
    return 0;
}
