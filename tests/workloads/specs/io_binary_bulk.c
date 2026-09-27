/* Bulk output that is entirely binary: every byte value, NUL bytes, bare CR,
 * bare LF, CRLF, 0x1A, and byte sequences that are not valid UTF-8.
 *
 *   argv[1]  size in MiB (required)
 *
 * linux-io-binary-stdout already covers "all 256 values, once, in order" in 256
 * bytes. This is the same hazard at volume, where the failures are different:
 * a chunked relay that does newline translation, stops at a NUL, decodes to
 * text and re-encodes, or treats 0x1A as end-of-file corrupts this and not the
 * 256-byte version.
 *
 * The specimen counts what it emitted, so the claim is not "it is binary" but a
 * histogram: BINARY_VALUES_SEEN must be 256, and every count is reported. The
 * counts are deterministic -- the generator is a fixed-seed xorshift and the
 * hazard sequences are injected at fixed offsets -- but they are not values a
 * human can predict, so the declaration asserts the properties (all 256 values
 * present, the sequences present at those offsets, the digest verified) and the
 * baseline records the numbers.
 */
#include "oracle.h"
#include "orc_bulk.h"

#define CHUNK (64u * 1024u)

/* Injected at fixed offsets from the start of the stream. Each is a thing that
 * something along the way is known to mishandle. */
static const uint8_t HAZARD_CRLF[]    = { 0x0d, 0x0a, 0x0d, 0x0a };
static const uint8_t HAZARD_CR[]      = { 0x0d, 0x0d, 0x0d, 0x0d };
static const uint8_t HAZARD_NUL[]     = { 0, 0, 0, 0, 0, 0, 0, 0 };
static const uint8_t HAZARD_DOSEOF[]  = { 0x1a, 0x1a };
static const uint8_t HAZARD_BADUTF[]  = { 0xc3, 0x28, 0xed, 0xa0, 0x80, 0xff, 0xfe, 0xc0, 0x80 };

struct hazard { unsigned long long off; const uint8_t *bytes; size_t n; const char *name; };

int main(int argc, char **argv) {
    static uint8_t buf[CHUNK];
    static unsigned long long hist[256];
    orb_rng rng;
    orb_sha256 sha;
    char hex[65];
    unsigned long long want, written = 0, nul_count;
    unsigned long fnv = 14695981039346656037UL;
    int seen = 0, i, all_hazards_placed = 1;
    size_t h;
    const char *id = getenv("FIXTURE_ID");

    struct hazard hazards[] = {
        { 1024,           HAZARD_CRLF,    sizeof HAZARD_CRLF,   "crlf"    },
        { 4096,           HAZARD_CR,      sizeof HAZARD_CR,     "cr"      },
        { 65536 - 2,      HAZARD_NUL,     sizeof HAZARD_NUL,    "nul"     },  /* straddles a chunk edge */
        { 1048576,        HAZARD_DOSEOF,  sizeof HAZARD_DOSEOF, "doseof"  },
        { 1048576 + 64,   HAZARD_BADUTF,  sizeof HAZARD_BADUTF, "badutf8" },
    };

    setvbuf(stderr, NULL, _IOLBF, 0);
    fprintf(stderr, "FIXTURE_ID=%s\n", id ? id : "linux-io-binary-bulk");
    if (argc < 2) {
        fprintf(stderr, "USAGE=io_binary_bulk <mib>\nRESULT=FAIL\n");
        return 2;
    }
    want = strtoull(argv[1], NULL, 10) * 1024ull * 1024ull;
    if (want < 2ull * 1024ull * 1024ull) {
        fprintf(stderr, "TOO_SMALL_FOR_HAZARDS=yes\nRESULT=FAIL\n");
        return 2;
    }
    fprintf(stderr, "BINARY_REQUESTED_BYTES=%llu\n", want);
    fprintf(stderr, "BINARY_CHUNK_BYTES=%u\n", CHUNK);

    orb_rng_init(&rng);
    orb_sha256_init(&sha);
    memset(hist, 0, sizeof hist);

    while (written < want) {
        size_t c = (want - written < CHUNK) ? (size_t)(want - written) : CHUNK;
        size_t k;
        orb_fill(&rng, buf, c);
        /* The first 256 bytes are the ordered ramp, so "every value present" is
         * guaranteed by construction and not by luck. */
        if (written == 0) {
            for (k = 0; k < 256 && k < c; k++) buf[k] = (uint8_t)k;
        }
        /* Hazard sequences, written over the stream at absolute offsets. A
         * sequence may straddle the boundary between two chunks, which is
         * deliberate: that is where a relay with a fixed buffer breaks. */
        for (h = 0; h < sizeof hazards / sizeof hazards[0]; h++) {
            unsigned long long start = hazards[h].off;
            size_t j;
            for (j = 0; j < hazards[h].n; j++) {
                unsigned long long abs_off = start + j;
                if (abs_off >= written && abs_off < written + c)
                    buf[abs_off - written] = hazards[h].bytes[j];
            }
        }
        for (k = 0; k < c; k++) {
            hist[buf[k]]++;
            fnv ^= buf[k];
            fnv *= 1099511628211UL;
        }
        orb_sha256_update(&sha, buf, c);
        if (orb_write_all(1, buf, c) != 0) {
            fprintf(stderr, "WRITE_FAILED_AT=%llu\nWRITE_ERRNO=%s\nRESULT=FAIL\n",
                    written, orc_errno_name(errno));
            return 1;
        }
        written += c;
    }
    orb_sha256_final(&sha, hex);

    for (i = 0; i < 256; i++) if (hist[i]) seen++;
    nul_count = hist[0];
    for (h = 0; h < sizeof hazards / sizeof hazards[0]; h++)
        if (hazards[h].off + hazards[h].n > want) all_hazards_placed = 0;

    fprintf(stderr, "BINARY_BYTES=%llu\n", written);
    fprintf(stderr, "BINARY_SHA256=%s\n", hex);
    fprintf(stderr, "BINARY_FNV1A=%016lx\n", fnv);
    fprintf(stderr, "BINARY_VALUES_SEEN=%d\n", seen);
    fprintf(stderr, "BINARY_NUL_COUNT=%llu\n", nul_count);
    fprintf(stderr, "BINARY_HAZARD_OFFSETS=");
    for (h = 0; h < sizeof hazards / sizeof hazards[0]; h++)
        fprintf(stderr, "%s%s@%llu", h > 0 ? "," : "", hazards[h].name, hazards[h].off);
    fprintf(stderr, "\n");
    orc_ekv("BINARY_ALL_HAZARDS_PLACED", "%s", all_hazards_placed ? "yes" : "no");
    orc_ekv("BINARY_ALL_256_VALUES", "%s", seen == 256 ? "yes" : "no");
    orc_ekv("BINARY_HAS_NUL", "%s", nul_count > 0 ? "yes" : "no");
    fprintf(stderr, "RESULT=%s\n",
            (seen == 256 && nul_count > 0 && all_hazards_placed && written == want)
            ? "PASS" : "FAIL");
    return 0;
}
