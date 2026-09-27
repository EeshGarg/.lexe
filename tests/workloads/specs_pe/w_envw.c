/* The wide environment: GetEnvironmentVariableW for each name in argv, reported
 * as UTF-8 hex. A layer that mangles non-ASCII environment values shows up here
 * and nowhere else. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    int i;
    orc_begin("pe-env-wide");
    for (i = 1; i < argc; i++) {
        wchar_t wname[256], value[1024];
        DWORD n;
        char k[160];
        MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wname, 256);
        SetLastError(0);
        n = GetEnvironmentVariableW(wname, value, 1024);
        snprintf(k, sizeof k, "WENV_%s_PRESENT", argv[i]);
        orc_kv(k, "%s", n > 0 ? "yes" : (GetLastError() == 0 ? "yes" : "no"));
        if (n > 0) {
            snprintf(k, sizeof k, "WENV_%s", argv[i]);
            orc_wide(k, value);
        }
    }
    orc_check("WIDE_ENV_READ", 1);
    return orc_end();
}
