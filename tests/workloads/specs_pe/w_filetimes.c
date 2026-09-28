/* File TIMESTAMPS: SetFileTime with an exact FILETIME, read back with GetFileTime,
 * and converted both ways through FileTimeToSystemTime.
 *
 * A FILETIME is 100-nanosecond ticks since 1601-01-01 UTC. A Unix timestamp is
 * seconds since 1970 and, on most filesystems, nanoseconds beside it. So a
 * translation layer has to convert, and the two places it goes wrong are the epoch
 * offset and the resolution. Both show up here, because the value chosen is exact
 * and NOT a whole second:
 *
 *   0x01C0000000000001 ticks -- deliberately one tick past a round number, so a
 *   layer that stores whole seconds loses the low digits and a layer that gets the
 *   epoch wrong reports a completely different year.
 *
 * 0x01C0000000000001 is 126100789566373889 ticks, which is
 * 2000-08-06T23:42:36.637Z. That was computed from the DEFINITION of a FILETIME
 * before the specimen was ever run, not read off a run -- and the SYSTEMTIME round
 * trip must therefore lose exactly 3889 ticks, because a SYSTEMTIME stops at
 * milliseconds and 6373889 truncates to 6370000.
 */
#include "oracle_win.h"

static const wchar_t *NAME = L"times.dat";

int main(void) {
    HANDLE h;
    DWORD written = 0;
    FILETIME want, created, accessed, modified;
    SYSTEMTIME st;
    orc_begin("pe-fs-file-times");

    DeleteFileW(NAME);
    h = CreateFileW(NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("CREATE", h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) { orc_werr_now("CREATE_ERROR"); return orc_end(); }
    WriteFile(h, "times", 5, &written, NULL);

    want.dwHighDateTime = 0x01C00000u;
    want.dwLowDateTime = 0x00000001u;
    orc_kv("REQUESTED_FILETIME_HEX", "%08lx%08lx",
           (unsigned long)want.dwHighDateTime, (unsigned long)want.dwLowDateTime);

    orc_check("SET_FILE_TIME", SetFileTime(h, &want, &want, &want) != 0);
    ZeroMemory(&created, sizeof created);
    ZeroMemory(&accessed, sizeof accessed);
    ZeroMemory(&modified, sizeof modified);
    orc_check("GET_FILE_TIME", GetFileTime(h, &created, &accessed, &modified) != 0);
    orc_kv("MODIFIED_FILETIME_HEX", "%08lx%08lx",
           (unsigned long)modified.dwHighDateTime, (unsigned long)modified.dwLowDateTime);
    orc_kv("CREATED_FILETIME_HEX", "%08lx%08lx",
           (unsigned long)created.dwHighDateTime, (unsigned long)created.dwLowDateTime);
    orc_check("MODIFIED_TIME_ROUNDTRIPPED_EXACTLY",
              modified.dwHighDateTime == want.dwHighDateTime
              && modified.dwLowDateTime == want.dwLowDateTime);
    orc_check("FILETIME_RESOLUTION_NOT_LOST_TO_SECONDS",
              modified.dwLowDateTime == want.dwLowDateTime);

    ZeroMemory(&st, sizeof st);
    orc_check("FILETIME_TO_SYSTEMTIME", FileTimeToSystemTime(&want, &st) != 0);
    orc_kv("SYSTEMTIME", "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
           (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
           (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
           (unsigned)st.wMilliseconds);
    {
        FILETIME back;
        ZeroMemory(&back, sizeof back);
        orc_check("SYSTEMTIME_TO_FILETIME", SystemTimeToFileTime(&st, &back) != 0);
        /* A SYSTEMTIME has millisecond resolution, so the round trip must lose the
         * sub-millisecond ticks and NOTHING MORE. That difference is exact. */
        orc_kv("ROUNDTRIP_TICK_DIFFERENCE", "%llu",
               ((unsigned long long)want.dwHighDateTime << 32 | want.dwLowDateTime)
               - ((unsigned long long)back.dwHighDateTime << 32 | back.dwLowDateTime));
    }
    CloseHandle(h);

    /* The times must survive closing the handle, which is where a layer that only
     * cached them in memory is caught. */
    h = CreateFileW(NAME, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("REOPEN", h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        FILETIME m2;
        ZeroMemory(&m2, sizeof m2);
        GetFileTime(h, NULL, NULL, &m2);
        orc_kv("MODIFIED_AFTER_REOPEN_HEX", "%08lx%08lx",
               (unsigned long)m2.dwHighDateTime, (unsigned long)m2.dwLowDateTime);
        orc_check("TIME_PERSISTED_TO_DISK",
                  m2.dwHighDateTime == want.dwHighDateTime
                  && m2.dwLowDateTime == want.dwLowDateTime);
        CloseHandle(h);
    }

    /* And the same value through the by-name API, which is a different code path. */
    {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        ZeroMemory(&fad, sizeof fad);
        orc_check("GET_FILE_ATTRIBUTES_EX",
                  GetFileAttributesExW(NAME, GetFileExInfoStandard, &fad) != 0);
        orc_kv("BY_NAME_MODIFIED_HEX", "%08lx%08lx",
               (unsigned long)fad.ftLastWriteTime.dwHighDateTime,
               (unsigned long)fad.ftLastWriteTime.dwLowDateTime);
        orc_kv("BY_NAME_SIZE_LOW", "%lu", (unsigned long)fad.nFileSizeLow);
        orc_check("BY_NAME_AGREES_WITH_BY_HANDLE",
                  fad.ftLastWriteTime.dwHighDateTime == want.dwHighDateTime
                  && fad.ftLastWriteTime.dwLowDateTime == want.dwLowDateTime);
    }

    orc_check("DELETE", DeleteFileW(NAME) != 0);
    return orc_end();
}
