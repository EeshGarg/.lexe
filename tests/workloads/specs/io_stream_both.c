/* Large volumes on stdout AND stderr at the same time, strictly interleaved.
 *
 *   argv[1]  size in MiB for EACH stream (required)
 *
 * This is the shape that deadlocks a naive relay. A reader that drains stdout
 * to EOF before looking at stderr will block forever once the stderr pipe
 * buffer fills (64 KiB by default on Linux), because the program is then
 * blocked writing to stderr and will never close stdout. The two streams have
 * to be read concurrently -- poll/select, two threads, or non-blocking fds --
 * and a program like this is the only thing that proves it.
 *
 * The writes alternate in 64 KiB units and go straight to the fds, so the
 * interleaving is the program's and not stdio's.
 *
 * Where the oracle goes, and why: BOTH streams are bulk, so there is no spare
 * stream to report on. The stderr payload is therefore deliberately made of
 * lines of lowercase hex containing no '=' character, so no payload line can
 * ever parse as a KEY=VALUE line, and the oracle is appended to stderr after
 * the payload ends. The specimen attests to the length and SHA-256 of the
 * stderr PAYLOAD as distinct from the whole stderr stream, and reports exactly
 * where the payload starts, so the claim stays checkable:
 *
 *     sha256(stderr[ERR_PAYLOAD_OFFSET : +ERR_PAYLOAD_BYTES]) == ERR_PAYLOAD_SHA256
 *
 * Every byte this program puts on stderr goes through one function that both
 * writes it and counts it, so the offset it reports cannot drift out of step
 * with the bytes it wrote. An earlier version recomputed the offset from copies
 * of the format strings, which is a fixture that lies the moment a header line
 * is edited.
 */
#include "oracle.h"
#include "orc_bulk.h"

#define CHUNK (64u * 1024u)

static unsigned long long err_written = 0;

/* Every stderr byte written by this specimen passes through here. */
static int eout(const char *fmt, ...) {
    char line[512];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= sizeof line) n = (int)sizeof line - 1;
    if (orb_write_all(2, line, (size_t)n) != 0) return -1;
    err_written += (unsigned long long)n;
    return n;
}

/* 1023 hex characters then a newline, repeating: exactly CHUNK bytes, no '='
 * anywhere, and a deterministic function of the generator. */
static void fill_hex_lines(orb_rng *r, uint8_t *buf, size_t n) {
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        if ((i % 1024) == 1023) buf[i] = '\n';
        else buf[i] = (uint8_t)digits[orb_rng_byte(r) & 0xf];
    }
}

int main(int argc, char **argv) {
    static uint8_t obuf[CHUNK];
    static uint8_t ebuf[CHUNK];
    orb_rng orng, erng;
    orb_sha256 osha, esha;
    char ohex[65], ehex[65];
    unsigned long long want, owritten = 0, epayload = 0, offset;
    const char *id = getenv("FIXTURE_ID");
    int ok;

    eout("FIXTURE_ID=%s\n", id ? id : "linux-io-stream-both");
    if (argc < 2) {
        eout("USAGE=io_stream_both <mib-per-stream>\nRESULT=FAIL\n");
        return 2;
    }
    want = strtoull(argv[1], NULL, 10) * 1024ull * 1024ull;
    eout("BOTH_REQUESTED_BYTES_PER_STREAM=%llu\n", want);
    eout("BOTH_CHUNK_BYTES=%u\n", CHUNK);
    eout("BOTH_PAYLOAD_BEGINS=here\n");
    offset = err_written;

    /* Two independent generators, so the streams are not copies of each other
     * and a relay that crosses them shows up as a digest mismatch rather than
     * as nothing at all. */
    orb_rng_init(&orng);
    erng.x = ORB_SEED ^ 0xA5A5A5A5A5A5A5A5ULL;
    orb_sha256_init(&osha);
    orb_sha256_init(&esha);

    while (owritten < want || epayload < want) {
        if (owritten < want) {
            size_t c = (want - owritten < CHUNK) ? (size_t)(want - owritten) : CHUNK;
            orb_fill(&orng, obuf, c);
            orb_sha256_update(&osha, obuf, c);
            if (orb_write_all(1, obuf, c) != 0) {
                eout("OUT_WRITE_FAILED_AT=%llu\nRESULT=FAIL\n", owritten);
                return 1;
            }
            owritten += c;
        }
        if (epayload < want) {
            size_t c = (want - epayload < CHUNK) ? (size_t)(want - epayload) : CHUNK;
            fill_hex_lines(&erng, ebuf, c);
            orb_sha256_update(&esha, ebuf, c);
            if (orb_write_all(2, ebuf, c) != 0) {
                /* Cannot report this on stderr. stdout is binary, but reachable. */
                dprintf(1, "\nERR_WRITE_FAILED_AT=%llu\n", epayload);
                return 1;
            }
            err_written += (unsigned long long)c;
            epayload += c;
        }
    }
    orb_sha256_final(&osha, ohex);
    orb_sha256_final(&esha, ehex);

    ok = (owritten == want && epayload == want);
    eout("\n");                      /* the payload's last line need not be whole */
    eout("ERR_PAYLOAD_OFFSET=%llu\n", offset);
    eout("OUT_BYTES=%llu\n", owritten);
    eout("OUT_SHA256=%s\n", ohex);
    eout("ERR_PAYLOAD_BYTES=%llu\n", epayload);
    eout("ERR_PAYLOAD_SHA256=%s\n", ehex);
    eout("BOTH_STREAMS_COMPLETE=%s\n", ok ? "yes" : "no");
    eout("RESULT=%s\n", ok ? "PASS" : "FAIL");
    return 0;
}
