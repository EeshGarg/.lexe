/* File ATTRIBUTES, the Windows ones that have no Unix mode bit behind them:
 * READONLY, HIDDEN, ARCHIVE, and the way READONLY blocks deletion. A layer has to
 * store these somewhere -- Wine keeps them partly in the Unix permission bits and
 * partly nowhere -- and an installer that sets a file read-only and then cannot
 * delete it is depending on the answer.
 */
#include "oracle_win.h"

static const wchar_t *NAME = L"attrs.dat";

static void report_attrs(const char *label) {
    char key[128];
    DWORD a = GetFileAttributesW(NAME);
    snprintf(key, sizeof key, "%s_PRESENT", label);
    orc_kv(key, "%s", a != INVALID_FILE_ATTRIBUTES ? "yes" : "no");
    if (a == INVALID_FILE_ATTRIBUTES) return;
    snprintf(key, sizeof key, "%s_READONLY", label);
    orc_kv(key, "%s", (a & FILE_ATTRIBUTE_READONLY) ? "yes" : "no");
    snprintf(key, sizeof key, "%s_HIDDEN", label);
    orc_kv(key, "%s", (a & FILE_ATTRIBUTE_HIDDEN) ? "yes" : "no");
    snprintf(key, sizeof key, "%s_DIRECTORY", label);
    orc_kv(key, "%s", (a & FILE_ATTRIBUTE_DIRECTORY) ? "yes" : "no");
}

int main(void) {
    HANDLE h;
    DWORD written = 0;
    orc_begin("pe-fs-file-attributes");

    SetFileAttributesW(NAME, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(NAME);
    h = CreateFileW(NAME, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("CREATE", h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) { orc_werr_now("CREATE_ERROR"); return orc_end(); }
    WriteFile(h, "attributes", 10, &written, NULL);
    CloseHandle(h);
    report_attrs("FRESH");

    orc_check("SET_READONLY", SetFileAttributesW(NAME, FILE_ATTRIBUTE_READONLY) != 0);
    report_attrs("AFTER_READONLY");

    /* A read-only file cannot be opened for writing, and cannot be deleted. */
    SetLastError(0);
    h = CreateFileW(NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    orc_kv("OPEN_READONLY_FOR_WRITE", "%s", h != INVALID_HANDLE_VALUE ? "opened" : "refused");
    orc_werr_now("OPEN_READONLY_FOR_WRITE_ERROR");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    SetLastError(0);
    orc_kv("DELETE_READONLY", "%s", DeleteFileW(NAME) ? "deleted" : "refused");
    orc_werr_now("DELETE_READONLY_ERROR");

    /* Reading it is still fine. */
    h = CreateFileW(NAME, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("READ_READONLY", h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[32];
        DWORD n = 0;
        ReadFile(h, buf, sizeof buf - 1, &n, NULL);
        buf[n] = 0;
        CloseHandle(h);
        orc_check("READONLY_CONTENT_INTACT", strcmp(buf, "attributes") == 0);
    }

    orc_check("SET_HIDDEN",
              SetFileAttributesW(NAME, FILE_ATTRIBUTE_HIDDEN) != 0);
    report_attrs("AFTER_HIDDEN");
    /* A hidden file is still found by an explicit name, unlike in some shells. */
    orc_check("HIDDEN_STILL_OPENABLE",
              (h = CreateFileW(NAME, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    orc_check("CLEAR_ATTRS", SetFileAttributesW(NAME, FILE_ATTRIBUTE_NORMAL) != 0);
    report_attrs("AFTER_CLEAR");
    orc_check("DELETE_AFTER_CLEAR", DeleteFileW(NAME) != 0);
    orc_check("GONE", GetFileAttributesW(NAME) == INVALID_FILE_ATTRIBUTES);

    SetLastError(0);
    orc_kv("ATTRS_OF_ABSENT_FILE", "%s",
           GetFileAttributesW(L"no-such-file-at-all.dat") == INVALID_FILE_ATTRIBUTES
           ? "invalid" : "reported");
    orc_werr_now("ATTRS_OF_ABSENT_FILE_ERROR");
    return orc_end();
}
