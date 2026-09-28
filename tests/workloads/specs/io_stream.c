/* A large, verifiable stream on stdout, and nothing else on stdout.
 *
 *   argv[1]  size in MiB          (required)
 *   argv[2]  exit code            (optional, default 0)
 *
 * One source, several specimens: the stream is a pure function of the offset,
 * so 4 MiB is a prefix of 64 MiB, which is a prefix of 256 MiB. The size is
 * declared per specimen in the generator table rather than compiled in, because
 * the property being explored is volume and the only way to explore volume is
 * to vary it.
 *
 * The specimen attests to what it wrote -- byte count, SHA-256 and FNV-1a --
 * on stderr, and the runner recomputes both over the stream it captured. That
 * is the whole point: a length check alone cannot tell a truncated stream from
 * a reordered one, or from one whose NUL bytes were eaten.
 *
 * Nothing here is buffered by stdio (see orb_write_all): what the program asks
 * the kernel to write is exactly what it claims to have written.
 */
#include "oracle.h"
#include "orc_bulk.h"

#define CHUNK (64u * 1024u)

int main(int argc, char **argv) {
    static uint8_t buf[CHUNK];
    orb_rng rng;
    orb_sha256 sha;
    char hex[65];
    unsigned long long want, written = 0;
    unsigned long fnv = 14695981039346656037UL;
    int exit_code = 0;

    orc_ebegin("linux-io-stream");
    if (argc < 2) {
        fprintf(stderr, "USAGE=io_stream <mib> [exit_code]\nRESULT=FAIL\n");
        return 2;
    }
    want = strtoull(argv[1], NULL, 10) * 1024ull * 1024ull;
    if (argc > 2) exit_code = atoi(argv[2]);

    fprintf(stderr, "STREAM_REQUESTED_BYTES=%llu\n", want);
    fprintf(stderr, "STREAM_CHUNK_BYTES=%u\n", CHUNK);
    fprintf(stderr, "STREAM_DECLARED_EXIT=%d\n", exit_code);
    /* Announced BEFORE the bulk starts, so a consumer that never drains stdout
     * still has the claim on stderr and can see how far it got. */

    orb_rng_init(&rng);
    orb_sha256_init(&sha);
    while (written < want) {
        size_t c = (want - written < CHUNK) ? (size_t)(want - written) : CHUNK;
        size_t i;
        orb_fill(&rng, buf, c);
        orb_sha256_update(&sha, buf, c);
        for (i = 0; i < c; i++) { fnv ^= buf[i]; fnv *= 1099511628211UL; }
        if (orb_write_all(1, buf, c) != 0) {
            fprintf(stderr, "WRITE_FAILED_AT=%llu\nWRITE_ERRNO=%s\nRESULT=FAIL\n",
                    written, orc_errno_name(errno));
            return 1;
        }
        written += c;
    }
    orb_sha256_final(&sha, hex);

    fprintf(stderr, "STREAM_BYTES=%llu\n", written);
    fprintf(stderr, "STREAM_SHA256=%s\n", hex);
    fprintf(stderr, "STREAM_FNV1A=%016lx\n", fnv);
    fprintf(stderr, "STREAM_COMPLETE=%s\n", written == want ? "yes" : "no");
    fprintf(stderr, "EXIT_CODE=%d\n", exit_code);
    fprintf(stderr, "RESULT=%s\n", written == want ? "PASS" : "FAIL");
    return exit_code;
}
