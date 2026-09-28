/* Overlapped (asynchronous) file I/O, the Windows model that has no direct POSIX
 * equivalent: the OVERLAPPED structure carries the OFFSET, the call may return
 * before the work is done, and the caller collects the result later with
 * GetOverlappedResult or by waiting on an event.
 *
 * Two things a layer commonly gets wrong are pinned down here:
 *   1. with FILE_FLAG_OVERLAPPED the file pointer is IGNORED -- the offset in the
 *      OVERLAPPED is the only thing that decides where the bytes go, and a layer
 *      that quietly uses the file pointer instead writes them in the wrong place;
 *   2. an operation that has not finished reports ERROR_IO_PENDING, and that is a
 *      success, not a failure.
 *
 * The same handle is used for three writes at three declared offsets, out of
 * order, and the resulting file is checked byte for byte.
 */
#include "oracle_win.h"

static const wchar_t *NAME = L"overlapped.dat";

static int write_at(HANDLE h, const char *text, DWORD len, DWORD offset,
                    const char *label) {
    OVERLAPPED ov;
    DWORD done = 0;
    char key[128];
    BOOL ok;
    ZeroMemory(&ov, sizeof ov);
    ov.Offset = offset;
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    SetLastError(0);
    ok = WriteFile(h, text, len, NULL, &ov);
    snprintf(key, sizeof key, "%s_IMMEDIATE", label);
    orc_kv(key, "%s", ok ? "completed" : "deferred");
    if (!ok) {
        snprintf(key, sizeof key, "%s_DEFERRED_ERROR", label);
        orc_werr_now(key);
        if (GetLastError() != ERROR_IO_PENDING) { CloseHandle(ov.hEvent); return 0; }
    }
    ok = GetOverlappedResult(h, &ov, &done, TRUE);
    snprintf(key, sizeof key, "%s_RESULT", label);
    orc_kv(key, "%s", ok ? "ok" : "fail");
    snprintf(key, sizeof key, "%s_BYTES", label);
    orc_kv(key, "%lu", (unsigned long)done);
    CloseHandle(ov.hEvent);
    return ok && done == len;
}

int main(void) {
    HANDLE h;
    orc_begin("pe-fs-overlapped-io");

    DeleteFileW(NAME);
    h = CreateFileW(NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_FLAG_OVERLAPPED, NULL);
    orc_check("CREATE_OVERLAPPED", h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) { orc_werr_now("CREATE_ERROR"); return orc_end(); }

    /* Deliberately out of order, and deliberately not from zero. */
    orc_check("WRITE_MIDDLE", write_at(h, "MIDDLE--", 8, 16, "MIDDLE"));
    orc_check("WRITE_FIRST", write_at(h, "FIRST---", 8, 0, "FIRST"));
    orc_check("WRITE_LAST", write_at(h, "LAST----", 8, 32, "LAST"));

    {
        OVERLAPPED ov;
        char buf[40];
        DWORD done = 0;
        BOOL ok;
        ZeroMemory(&ov, sizeof ov);
        ov.Offset = 0;
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        SetLastError(0);
        ok = ReadFile(h, buf, 40, NULL, &ov);
        orc_kv("READ_IMMEDIATE", "%s", ok ? "completed" : "deferred");
        if (!ok) orc_werr_now("READ_DEFERRED_ERROR");
        ok = GetOverlappedResult(h, &ov, &done, TRUE);
        CloseHandle(ov.hEvent);
        orc_check("OVERLAPPED_READ", ok != 0);
        orc_kv("READ_BYTES", "%lu", (unsigned long)done);
        orc_check("READ_WHOLE_FILE", done == 40);
        if (done == 40) {
            orc_check("FIRST_AT_OFFSET_0", memcmp(buf + 0, "FIRST---", 8) == 0);
            orc_check("MIDDLE_AT_OFFSET_16", memcmp(buf + 16, "MIDDLE--", 8) == 0);
            orc_check("LAST_AT_OFFSET_32", memcmp(buf + 32, "LAST----", 8) == 0);
            orc_check("GAPS_ARE_ZEROS",
                      buf[8] == 0 && buf[15] == 0 && buf[24] == 0 && buf[31] == 0);
            orc_kv("FILE_HASH", "%016llx", orc_fnv1a((const unsigned char *)buf, 40));
        }
    }

    /* Reading past the end of an overlapped file has its own answer: not zero
     * bytes as in the synchronous case, but ERROR_HANDLE_EOF. */
    {
        OVERLAPPED ov;
        char buf[8];
        DWORD done = 0xFFFFFFFFu;
        ZeroMemory(&ov, sizeof ov);
        ov.Offset = 4096;
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        SetLastError(0);
        if (!ReadFile(h, buf, 8, NULL, &ov) && GetLastError() == ERROR_IO_PENDING)
            GetOverlappedResult(h, &ov, &done, TRUE);
        else
            done = 0;
        orc_werr_now("READ_PAST_END_ERROR");
        orc_kv("READ_PAST_END_BYTES", "%lu", (unsigned long)done);
        CloseHandle(ov.hEvent);
    }

    CloseHandle(h);
    orc_check("DELETE", DeleteFileW(NAME) != 0);
    return orc_end();
}
