/* Binary output, NUL bytes included.
 *
 * Emits all 256 byte values four times over -- 1024 bytes containing four NULs,
 * four 0x0A newlines and four 0x1A DOS-EOFs -- to binary.out AND to stdout,
 * bracketed by delimiter lines.
 *
 * Two Windows-specific things make this worth its own specimen:
 *   - stdout must be put into _O_BINARY first, or the C runtime turns every 0x0A
 *     in the payload into 0x0D 0x0A and the bytes that come out are not the bytes
 *     that went in;
 *   - the same applies to the FILE, which is why it is opened "wb".
 *
 * The deterministic claims are all about binary.out, which carries nothing but
 * the payload. Nothing here reports an offset into stdout, because stdout also
 * carries FIXTURE_ID: the payload is located in the stream by the delimiter
 * lines, and the absolute offset is an observation.
 */
#include "oracle_win.h"

#ifdef _WIN32
#  include <fcntl.h>
#  include <io.h>
#endif

#define BEGIN_DELIM "BIN_PAYLOAD_BEGIN"
#define END_DELIM   "BIN_PAYLOAD_END"
#define REPEATS 4

int main(void) {
    unsigned char payload[256 * REPEATS];
    unsigned i;
    FILE *out;
    orc_begin("pe-io-binary-nul");

    for (i = 0; i < 256u * REPEATS; i++) payload[i] = (unsigned char)(i & 0xFF);

#ifdef _WIN32
    orc_kv("STDOUT_BINARY_MODE", "%s",
           _setmode(_fileno(stdout), _O_BINARY) != -1 ? "ok" : "fail");
#else
    orc_kv("STDOUT_BINARY_MODE", "not-applicable");
#endif

    out = fopen("binary.out", "wb");
    orc_check("BIN_FILE_OPEN", out != NULL);
    if (!out) return orc_end();
    fwrite(payload, 1, sizeof payload, out);
    fclose(out);

    fputs(BEGIN_DELIM "\n", stdout);
    fflush(stdout);
    fwrite(payload, 1, sizeof payload, stdout);
    fflush(stdout);
    fputs("\n" END_DELIM "\n", stdout);
    fflush(stdout);
    orc_kv("BIN_DELIMITERS", "%s..%s", BEGIN_DELIM, END_DELIM);

    /* Read the file back and describe it: every one of these is a property of
     * the payload, over a file that never carried anything else. */
    out = fopen("binary.out", "rb");
    orc_check("BIN_FILE_REOPEN", out != NULL);
    if (out) {
        unsigned char got[256 * REPEATS + 16];
        size_t n = fread(got, 1, sizeof got, out);
        unsigned counts[256];
        unsigned nuls = 0, newlines = 0, dos_eofs = 0, distinct = 0;
        int identical;
        fclose(out);
        memset(counts, 0, sizeof counts);
        for (i = 0; i < (unsigned)n; i++) counts[got[i]]++;
        for (i = 0; i < 256; i++) if (counts[i]) distinct++;
        nuls = counts[0x00];
        newlines = counts[0x0A];
        dos_eofs = counts[0x1A];
        identical = (n == sizeof payload) && memcmp(got, payload, n) == 0;
        orc_kv("BIN_FILE_BYTES", "%lu", (unsigned long)n);
        orc_kv("BIN_FILE_HASH", "%016llx", orc_fnv1a(got, n));
        orc_kv("BIN_DISTINCT_BYTE_VALUES", "%u", distinct);
        orc_kv("BIN_NUL_COUNT", "%u", nuls);
        orc_kv("BIN_NEWLINE_COUNT", "%u", newlines);
        orc_kv("BIN_DOS_EOF_COUNT", "%u", dos_eofs);
        orc_check("BIN_ROUNDTRIP_IDENTICAL", identical);
        orc_check("BIN_NO_NEWLINE_TRANSLATION", newlines == REPEATS);
    }
    orc_check("BIN_EMITTED", 1);
    return orc_end();
}
