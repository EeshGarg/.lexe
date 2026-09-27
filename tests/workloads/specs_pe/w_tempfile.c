/* Temporary state the Windows way: GetTempPathW then GetTempFileNameW, write,
 * read back, delete. Reports whether the temp path it was given is usable at
 * all -- a translation layer has to provide one. */
#include "oracle_win.h"

int main(void) {
    wchar_t dir[MAX_PATH], file[MAX_PATH];
    DWORD n;
    HANDLE h;
    DWORD written = 0;
    orc_begin("pe-fs-tempfile");
    n = GetTempPathW(MAX_PATH, dir);
    orc_check("GET_TEMP_PATH", n > 0 && n < MAX_PATH);
    if (!(n > 0 && n < MAX_PATH)) { orc_werr_now("TEMP_PATH_ERROR"); return orc_end(); }
    orc_obs("TEMP_PATH_LEN", "%lu", (unsigned long)n);
    if (GetTempFileNameW(dir, L"lxw", 0, file) == 0) {
        orc_check("GET_TEMP_FILE_NAME", 0);
        orc_werr_now("TEMP_FILE_ERROR");
        return orc_end();
    }
    orc_check("GET_TEMP_FILE_NAME", 1);
    h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    orc_check("OPEN_TEMP", h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        orc_check("WRITE_TEMP", WriteFile(h, "temp", 4, &written, NULL) != 0);
        CloseHandle(h);
    }
    orc_check("DELETE_TEMP", DeleteFileW(file) != 0);
    orc_check("TEMP_GONE", GetFileAttributesW(file) == INVALID_FILE_ATTRIBUTES);
    orc_kv("LEAVES_NO_TRACE", "yes");
    return orc_end();
}
