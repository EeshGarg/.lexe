/* A file whose NAME is not ASCII: created with CreateFileW, found again with
 * FindFirstFileW, read back, and deleted. The name is built from explicit code
 * points in the source so the source file encoding cannot change the test. */
#include "oracle_win.h"

int main(void) {
    /* "日本語-café.txt" as code points, not as source bytes. */
    static const wchar_t name[] = { 0x65E5, 0x672C, 0x8A9E, L'-', L'c', L'a', L'f',
                                    0x00E9, L'.', L't', L'x', L't', 0 };
    HANDLE h;
    DWORD written = 0, read_back = 0;
    char buf[64];
    WIN32_FIND_DATAW fd;
    HANDLE find;
    const char *payload = "unicode-path-payload";
    orc_begin("pe-fs-unicode-path");
    orc_wide("TARGET_NAME", name);
    DeleteFileW(name);
    h = CreateFileW(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("CREATE_FILE_W", h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) { orc_werr_now("CREATE_ERROR"); return orc_end(); }
    orc_check("WRITE_FILE", WriteFile(h, payload, (DWORD)strlen(payload), &written, NULL) != 0);
    orc_kv("BYTES_WRITTEN", "%lu", (unsigned long)written);
    CloseHandle(h);
    find = FindFirstFileW(name, &fd);
    orc_check("FIND_FIRST_FILE_W", find != INVALID_HANDLE_VALUE);
    if (find != INVALID_HANDLE_VALUE) {
        orc_wide("FOUND_NAME", fd.cFileName);
        orc_kv("FOUND_SIZE_LOW", "%lu", (unsigned long)fd.nFileSizeLow);
        FindClose(find);
    }
    h = CreateFileW(name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("REOPEN_BY_UNICODE_NAME", h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        ReadFile(h, buf, sizeof buf - 1, &read_back, NULL);
        buf[read_back] = 0;
        CloseHandle(h);
        orc_check("CONTENT_MATCHES", strcmp(buf, payload) == 0);
    }
    orc_check("DELETE_FILE_W", DeleteFileW(name) != 0);
    orc_check("GONE", GetFileAttributesW(name) == INVALID_FILE_ATTRIBUTES);
    return orc_end();
}
