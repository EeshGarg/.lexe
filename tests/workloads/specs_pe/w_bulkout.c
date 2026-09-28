/* Large output. argv[1] selects the stream (out, err, both), argv[2] how many
 * KiB of payload to emit.
 *
 * The payload is bracketed by DELIMITER LINES and written a second time to
 * bulk.bin, and that file is what the deterministic claims are about. That split
 * is deliberate: the corpus forbids a deterministic oracle value that is a byte
 * position, length or count over a stream that ALSO carries FIXTURE_ID, because
 * FIXTURE_ID is environment-derived and an offset measured past it moves when the
 * environment does. bulk.bin carries nothing but the payload, so its length and
 * hash are properties of the program. A consumer that wants the payload out of
 * the STREAM finds it between the two delimiter lines, by content, never by
 * offset -- the absolute offset is reported, as an observation.
 *
 * The payload is lowercase hex and newlines only, so it cannot contain either
 * delimiter.
 */
#include "oracle_win.h"

#define BEGIN_DELIM "BULK_PAYLOAD_BEGIN"
#define END_DELIM   "BULK_PAYLOAD_END"

static void fill(unsigned char *line, unsigned long index) {
    static const char *d = "0123456789abcdef";
    int i;
    for (i = 0; i < 63; i++)
        line[i] = (unsigned char)d[(unsigned)(index * 7u + (unsigned)i) & 0xf];
    line[63] = '\n';
}

int main(int argc, char **argv) {
    const char *which = argc > 1 ? argv[1] : "out";
    unsigned long kib = argc > 2 ? strtoul(argv[2], NULL, 10) : 256;
    unsigned long lines = kib * 16;             /* 64 bytes per line */
    unsigned long total = lines * 64;
    unsigned long long h = 14695981039346656037ULL;
    unsigned long i;
    unsigned char line[64];
    FILE *bulk;
    int to_out = strcmp(which, "err") != 0;
    int to_err = strcmp(which, "out") != 0;

    orc_begin("pe-io-bulk");
    orc_kv("BULK_STREAM", "%s", which);
    orc_kv("BULK_KIB", "%lu", kib);
    orc_kv("BULK_LINE_BYTES", "%d", 64);

    bulk = fopen("bulk.bin", "wb");
    orc_check("BULK_FILE_OPEN", bulk != NULL);
    if (!bulk) return orc_end();

    /* The delimiters go to every stream the payload goes to, so the region is
     * locatable by content in each of them independently. */
    if (to_out) { fputs(BEGIN_DELIM "\n", stdout); fflush(stdout); }
    if (to_err) { fputs(BEGIN_DELIM "\n", stderr); fflush(stderr); }
    for (i = 0; i < lines; i++) {
        fill(line, i);
        h = orc_fnv1a(line, 64) ^ h;
        h *= 1099511628211ULL;
        fwrite(line, 1, 64, bulk);
        if (to_out) fwrite(line, 1, 64, stdout);
        if (to_err) fwrite(line, 1, 64, stderr);
    }
    if (to_out) { fflush(stdout); fputs(END_DELIM "\n", stdout); fflush(stdout); }
    if (to_err) { fflush(stderr); fputs(END_DELIM "\n", stderr); fflush(stderr); }
    fclose(bulk);

    orc_kv("BULK_DELIMITERS", "%s..%s", BEGIN_DELIM, END_DELIM);
    orc_kv("BULK_ROLLING_HASH", "%016llx", h);

    /* Re-read the file the program just wrote: its length and content hash are
     * deterministic because nothing else was ever written to it. */
    bulk = fopen("bulk.bin", "rb");
    orc_check("BULK_FILE_REOPEN", bulk != NULL);
    if (bulk) {
        unsigned long got = 0;
        unsigned long long fh = 14695981039346656037ULL;
        unsigned char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, bulk)) > 0) {
            size_t k;
            for (k = 0; k < n; k++) { fh ^= (unsigned long long)buf[k]; fh *= 1099511628211ULL; }
            got += (unsigned long)n;
        }
        fclose(bulk);
        orc_kv("BULK_FILE_BYTES", "%lu", got);
        orc_kv("BULK_FILE_HASH", "%016llx", fh);
        orc_check("BULK_FILE_SIZE_AS_INTENDED", got == total);
    }
    orc_check("BULK_EMITTED", 1);
    return orc_end();
}
