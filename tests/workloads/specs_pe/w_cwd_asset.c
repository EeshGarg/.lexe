/* A working-directory assumption, the way real Windows applications have them:
 * it requires assets\\data.txt relative to the current directory, and reports
 * what GetCurrentDirectoryW says. */
#include "oracle_win.h"

int main(void) {
    wchar_t cwd[MAX_PATH];
    FILE *f;
    char line[128];
    orc_begin("pe-fs-cwd-relative-asset");
    if (GetCurrentDirectoryW(MAX_PATH, cwd)) orc_wide_obs("CWD", cwd);
    f = fopen("assets\\data.txt", "rb");
    orc_check("ASSET_OPENED_BACKSLASH", f != NULL);
    if (!f) {
        f = fopen("assets/data.txt", "rb");
        orc_kv("ASSET_OPENED_FORWARDSLASH", "%s", f ? "yes" : "no");
    }
    if (!f) { orc_kv("ASSET_CONTENT", "(none)"); return orc_end(); }
    if (!fgets(line, sizeof line, f)) line[0] = 0;
    fclose(f);
    {
        size_t l = strlen(line);
        while (l && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = 0;
    }
    orc_kv("ASSET_CONTENT", "%s", line);
    orc_check("ASSET_CONTENT_OK", strcmp(line, "relative-asset-v1") == 0);
    return orc_end();
}
