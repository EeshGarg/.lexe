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
 * lines of lowercase hex, and the oracle is appended to stderr after the payload
 * ends. The specimen attests to the length and SHA-256 of the stderr PAYLOAD as
 * distinct from the whole stderr stream, so the claim stays checkable.
 *
 * HOW THE PAYLOAD IS LOCATED, and why it is not a byte offset.
 *
 * The first version of this specimen reported ERR_PAYLOAD_OFFSET -- an absolute
 * byte position into stderr -- as a deterministic oracle value, and that was a
 * fixture that lied about what it measured. The offset counts the header lines
 * that precede the payload, one of which is `FIXTURE_ID=<id>`, and the id comes
 * from the environment. Anything that clears the environment (which .LEXE does
 * by design) makes the id fall back to the shorter compiled-in literal, the
 * header shrinks, and the offset moves by exactly the difference in id length --
 * 129 with the environment set, 122 without it. A value derived from the
 * environment cannot be declared deterministic, and reclassifying it as an
 * observation would have kept the payload unlocatable without trusting a number
 * nobody can predict.
 *
 * So the payload is FRAMED instead, and located by content:
 *
 *     FIXTURE_ID=<id>
 *     BOTH_REQUESTED_BYTES_PER_STREAM=<n>
 *     BOTH_CHUNK_BYTES=65536
 *     ERR_PAYLOAD_DELIMITER=<<<LEXE-BULK-STDERR-PAYLOAD>>>
 *     <<<LEXE-BULK-STDERR-PAYLOAD>>>          <- payload begins after this line
 *     ...exactly ERR_PAYLOAD_BYTES of payload...
 *     <<<LEXE-BULK-STDERR-PAYLOAD>>>          <- payload ended before this line
 *     OUT_BYTES=<n>
 *     ...
 *
 * The consumer finds "\n" + delimiter + "\n" and must find it exactly twice; the
 * payload is what lies between. The delimiter cannot occur inside the payload,
 * by construction and not by luck: the payload contains only the 16 lowercase
 * hex characters and '\n', so it can contain neither '<' nor '='. The
 * announcing line is not a false match either, because it is preceded by '='
 * rather than by '\n'. Length and digest then cross-check the slice.
 *
 * Nothing about that framing depends on the environment, the id, the sizes, or
 * the lengths of any header line. The absolute offset is still reported, as
 * OBS_ERR_PAYLOAD_OFFSET, because it is useful when diagnosing a stream that
 * arrived wrong -- but it is an observation and nothing compares it.
 *
 * Every byte this program puts on stderr still goes through one function that
 * both writes it and counts it, so the observation cannot drift out of step with
 * the bytes written. An even earlier version recomputed the offset from copies
 * of the format strings, which is a fixture that lies the moment a header line
 * is edited.
 */
#include "oracle.h"
#include "orc_bulk.h"

#define CHUNK (64u * 1024u)

/* Contains '<' and '>', neither of which the payload alphabet can produce. */
#define ERR_DELIM "<<<LEXE-BULK-STDERR-PAYLOAD>>>"

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

/* 1023 hex characters then a newline, repeating: exactly CHUNK bytes. The
 * alphabet is deliberately narrow -- [0-9a-f] and '\n' and nothing else -- so
 * the payload can contain neither a '=' that would parse as an oracle line nor a
 * '<' that would forge the frame delimiter. */
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
    eout("ERR_PAYLOAD_DELIMITER=%s\n", ERR_DELIM);
    eout("%s\n", ERR_DELIM);
    offset = err_written;        /* reported as an observation only */

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
    /* The payload's last line need not be whole, so the closing frame gets its
     * own newline. That newline is NOT part of the payload the digest covers. */
    eout("\n%s\n", ERR_DELIM);
    eout("OUT_BYTES=%llu\n", owritten);
    eout("OUT_SHA256=%s\n", ohex);
    eout("ERR_PAYLOAD_BYTES=%llu\n", epayload);
    eout("ERR_PAYLOAD_SHA256=%s\n", ehex);
    eout("BOTH_STREAMS_COMPLETE=%s\n", ok ? "yes" : "no");
    eout("OBS_ERR_PAYLOAD_OFFSET=%llu\n", offset);
    eout("RESULT=%s\n", ok ? "PASS" : "FAIL");
    return 0;
}
