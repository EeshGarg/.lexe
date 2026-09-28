/* Long and deep paths. Two different things, deliberately kept apart:
 *
 * 1. A DEEP path that is still shorter than MAX_PATH (260). Twelve nested
 *    directories with sixteen-character names, a file at the bottom, written and
 *    read back. This must work everywhere and is declared exactly.
 *
 * 2. A path LONGER than MAX_PATH, reached through the \\?\ prefix that turns off
 *    the Win32 path parser. Whether that works is a PLATFORM choice -- it depends
 *    on the filesystem the layer is sitting on and on how much of the \\?\
 *    handling the layer implements -- so the outcome is declared as either of two
 *    legitimate answers and reported with the error when it is refused. What is
 *    NOT optional is that the program survives either way and says which happened.
 *
 * The same long path is also tried WITHOUT the prefix, which is the case that is
 * supposed to fail: that is how an application discovers it needs the prefix.
 */
#include "oracle_win.h"

#define DEPTH 12
#define COMPONENT L"cccccccccccccccc"   /* 16 characters */

static wchar_t deep[1024];
static wchar_t longp[1024];

int main(void) {
    int i;
    HANDLE h;
    DWORD written = 0;
    orc_begin("pe-fs-deep-and-long-paths");

    /* Build the deep-but-legal tree one level at a time. */
    deep[0] = 0;
    wcscpy(deep, L"deep");
    CreateDirectoryW(deep, NULL);
    for (i = 0; i < DEPTH; i++) {
        wchar_t next[1024];
        _snwprintf(next, 1024, L"%s\\%ls", deep, COMPONENT);
        wcscpy(deep, next);
        if (!CreateDirectoryW(deep, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            orc_kv("FAILED_AT_DEPTH", "%d", i);
            orc_werr_now("CREATE_DEEP_ERROR");
            break;
        }
    }
    orc_kv("DEEP_DEPTH_REQUESTED", "%d", DEPTH);
    orc_kv("DEEP_RELATIVE_LENGTH", "%u", (unsigned)wcslen(deep));
    orc_check("CREATED_EVERY_LEVEL", i == DEPTH);

    {
        wchar_t file[1024];
        _snwprintf(file, 1024, L"%s\\leaf.dat", deep);
        h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        orc_check("CREATE_FILE_AT_DEPTH", h != INVALID_HANDLE_VALUE);
        if (h == INVALID_HANDLE_VALUE) orc_werr_now("CREATE_LEAF_ERROR");
        else {
            WriteFile(h, "deep-leaf", 9, &written, NULL);
            CloseHandle(h);
            h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
            orc_check("REOPEN_FILE_AT_DEPTH", h != INVALID_HANDLE_VALUE);
            if (h != INVALID_HANDLE_VALUE) {
                char buf[32];
                DWORD got = 0;
                ReadFile(h, buf, sizeof buf - 1, &got, NULL);
                buf[got] = 0;
                CloseHandle(h);
                orc_check("DEEP_CONTENT_MATCHES", strcmp(buf, "deep-leaf") == 0);
            }
            orc_check("DELETE_FILE_AT_DEPTH", DeleteFileW(file) != 0);
        }
    }

    /* Now the over-MAX_PATH case. The absolute path is built from the working
     * directory, so its total length is environment-dependent -- which is why the
     * length itself is an OBSERVATION and only the two outcomes are checked. */
    {
        wchar_t cwd[MAX_PATH];
        DWORD n = GetCurrentDirectoryW(MAX_PATH, cwd);
        if (n == 0 || n >= MAX_PATH) {
            orc_kv("LONG_PATH_ATTEMPTED", "no");
        } else {
            int k;
            _snwprintf(longp, 1024, L"%ls\\long", cwd);
            CreateDirectoryW(longp, NULL);
            /* Append 16-character components until the whole thing is over 260. */
            for (k = 0; k < 40 && wcslen(longp) < 300; k++) {
                wchar_t next[1024];
                wchar_t prefixed[1040];
                _snwprintf(next, 1024, L"%s\\%ls", longp, COMPONENT);
                wcscpy(longp, next);
                _snwprintf(prefixed, 1040, L"\\\\?\\%s", longp);
                if (!CreateDirectoryW(prefixed, NULL)
                    && GetLastError() != ERROR_ALREADY_EXISTS) {
                    orc_kv("LONG_PATH_CREATE_STOPPED_AT_LENGTH", "%u",
                           (unsigned)wcslen(longp));
                    orc_werr_now("LONG_PATH_CREATE_ERROR");
                    break;
                }
            }
            orc_obs("LONG_PATH_LENGTH", "%u", (unsigned)wcslen(longp));
            orc_kv("LONG_PATH_EXCEEDS_MAX_PATH", "%s",
                   wcslen(longp) > 260 ? "yes" : "no");
            orc_kv("LONG_PATH_ATTEMPTED", "yes");
            {
                wchar_t prefixed[1040];
                _snwprintf(prefixed, 1040, L"\\\\?\\%s\\leaf.dat", longp);
                SetLastError(0);
                h = CreateFileW(prefixed, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
                orc_kv("LONG_PATH_WITH_PREFIX", "%s",
                       h != INVALID_HANDLE_VALUE ? "created" : "refused");
                orc_werr_now("LONG_PATH_WITH_PREFIX_ERROR");
                if (h != INVALID_HANDLE_VALUE) {
                    WriteFile(h, "long-leaf", 9, &written, NULL);
                    CloseHandle(h);
                    DeleteFileW(prefixed);
                }
            }
            {
                wchar_t plain[1040];
                _snwprintf(plain, 1040, L"%s\\leaf2.dat", longp);
                SetLastError(0);
                h = CreateFileW(plain, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
                orc_kv("LONG_PATH_WITHOUT_PREFIX", "%s",
                       h != INVALID_HANDLE_VALUE ? "created" : "refused");
                orc_werr_now("LONG_PATH_WITHOUT_PREFIX_ERROR");
                if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); DeleteFileW(plain); }
            }
        }
    }
    orc_check("SURVIVED_BOTH_PATH_LENGTHS", 1);
    return orc_end();
}
