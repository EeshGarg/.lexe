/* File POSITION and SIZE: SetFilePointerEx, GetFileSizeEx, SetEndOfFile, and what
 * a file that was extended past its old end actually contains.
 *
 * Windows guarantees the gap reads as zeros. On Unix an lseek past the end and a
 * write makes a sparse hole that also reads as zeros, so the two agree -- but only
 * because both implement it, and a layer that simply seeks the host file and
 * forgets SetEndOfFile leaves the file SHORT, which nothing notices until something
 * reads it back.
 *
 *   write 100 bytes           -> size 100
 *   SetEndOfFile at 50        -> size 50, and the tail is gone
 *   SetEndOfFile at 200       -> size 200, and bytes 50..199 are all zero
 *   seek relative and from the end, and past the end
 *
 * Every offset here is into the specimen's own data file, which carries nothing but
 * this payload, so these are properties of the program and not of any stream.
 */
#include "oracle_win.h"

static const wchar_t *NAME = L"positions.dat";

static long long size_of(HANDLE h) {
    LARGE_INTEGER s;
    s.QuadPart = -1;
    if (!GetFileSizeEx(h, &s)) return -1;
    return (long long)s.QuadPart;
}

static long long seek(HANDLE h, long long off, DWORD from) {
    LARGE_INTEGER d, out;
    d.QuadPart = off;
    out.QuadPart = -1;
    if (!SetFilePointerEx(h, d, &out, from)) return -1;
    return (long long)out.QuadPart;
}

int main(void) {
    HANDLE h;
    unsigned char payload[100];
    unsigned i;
    DWORD written = 0, got = 0;
    orc_begin("pe-fs-file-position");

    for (i = 0; i < 100; i++) payload[i] = (unsigned char)(0x41 + (i % 26));
    DeleteFileW(NAME);
    h = CreateFileW(NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("CREATE", h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) { orc_werr_now("CREATE_ERROR"); return orc_end(); }

    orc_check("WRITE_100", WriteFile(h, payload, 100, &written, NULL) != 0 && written == 100);
    orc_kv("SIZE_AFTER_WRITE", "%lld", size_of(h));
    orc_kv("POSITION_AFTER_WRITE", "%lld", seek(h, 0, FILE_CURRENT));

    orc_kv("SEEK_FROM_BEGIN_10", "%lld", seek(h, 10, FILE_BEGIN));
    orc_kv("SEEK_RELATIVE_PLUS_5", "%lld", seek(h, 5, FILE_CURRENT));
    orc_kv("SEEK_FROM_END_MINUS_10", "%lld", seek(h, -10, FILE_END));
    orc_kv("SEEK_PAST_END_TO_500", "%lld", seek(h, 500, FILE_BEGIN));
    orc_kv("SIZE_UNCHANGED_BY_SEEK_PAST_END", "%lld", size_of(h));
    orc_check("SEEK_PAST_END_DOES_NOT_GROW_THE_FILE", size_of(h) == 100);

    seek(h, 50, FILE_BEGIN);
    orc_check("SET_END_OF_FILE_TRUNCATE", SetEndOfFile(h) != 0);
    orc_kv("SIZE_AFTER_TRUNCATE", "%lld", size_of(h));
    orc_check("TRUNCATED_TO_50", size_of(h) == 50);

    seek(h, 200, FILE_BEGIN);
    orc_check("SET_END_OF_FILE_EXTEND", SetEndOfFile(h) != 0);
    orc_kv("SIZE_AFTER_EXTEND", "%lld", size_of(h));
    orc_check("EXTENDED_TO_200", size_of(h) == 200);

    {
        unsigned char buf[256];
        unsigned zeros = 0, kept = 0;
        seek(h, 0, FILE_BEGIN);
        orc_check("READ_BACK", ReadFile(h, buf, 256, &got, NULL) != 0);
        orc_kv("READ_BYTES", "%lu", (unsigned long)got);
        for (i = 0; i < 50 && i < got; i++) if (buf[i] == payload[i]) kept++;
        for (i = 50; i < got; i++) if (buf[i] == 0) zeros++;
        orc_kv("SURVIVING_PAYLOAD_BYTES", "%u", kept);
        orc_kv("ZERO_FILLED_GAP_BYTES", "%u", zeros);
        orc_check("READ_STOPPED_AT_END_OF_FILE", got == 200);
        orc_check("FIRST_50_BYTES_UNCHANGED", kept == 50);
        orc_check("EXTENSION_READS_AS_ZEROS", zeros == 150);
    }

    /* A write at an explicit offset past the current end, the other way a file
     * grows: the intervening bytes must also read as zeros. */
    seek(h, 300, FILE_BEGIN);
    orc_check("WRITE_AT_300", WriteFile(h, "TAIL", 4, &written, NULL) != 0);
    orc_kv("SIZE_AFTER_TAIL_WRITE", "%lld", size_of(h));
    orc_check("FILE_GREW_TO_304", size_of(h) == 304);
    {
        unsigned char buf[8];
        seek(h, 250, FILE_BEGIN);
        ReadFile(h, buf, 8, &got, NULL);
        orc_check("HOLE_BEFORE_TAIL_IS_ZEROS",
                  got == 8 && buf[0] == 0 && buf[7] == 0);
        seek(h, 300, FILE_BEGIN);
        ReadFile(h, buf, 4, &got, NULL);
        orc_check("TAIL_IS_WHERE_IT_WAS_PUT", got == 4 && memcmp(buf, "TAIL", 4) == 0);
    }

    /* Reading AT the end of file is not an error: it returns zero bytes. */
    seek(h, 304, FILE_BEGIN);
    got = 0xFFFFFFFFu;
    orc_kv("READ_AT_EOF_SUCCEEDED", "%s",
           ReadFile(h, payload, 16, &got, NULL) ? "yes" : "no");
    orc_kv("READ_AT_EOF_BYTES", "%lu", (unsigned long)got);
    orc_check("READ_AT_EOF_RETURNS_ZERO_BYTES", got == 0);

    CloseHandle(h);
    orc_check("DELETE", DeleteFileW(NAME) != 0);
    return orc_end();
}
