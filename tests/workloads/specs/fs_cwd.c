/* A program with a working-directory assumption: it requires ./assets/data.txt
 * to exist relative to the CWD, and fails cleanly if the CWD is not what it
 * expects. The runner stages assets/data.txt for it. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    char cwd[4096];
    FILE *f;
    char line[128];
    orc_begin("linux-fs-cwd-relative-asset");
    if (getcwd(cwd, sizeof cwd)) orc_obs("CWD", "%s", cwd);
    else orc_obs("CWD", "(getcwd failed: %s)", orc_errno_name(errno));
    f = fopen("assets/data.txt", "r");
    orc_check("ASSET_OPENED", f != NULL);
    if (!f) {
        orc_kv("ASSET_ERRNO", "%s", orc_errno_name(errno));
        orc_kv("ASSET_CONTENT", "(none)");
        return orc_end();
    }
    if (!fgets(line, sizeof line, f)) line[0] = 0;
    fclose(f);
    {
        size_t l = strlen(line);
        while (l && (line[l-1] == 10 || line[l-1] == 13)) line[--l] = 0;
    }
    orc_kv("ASSET_CONTENT", "%s", line);
    orc_check("ASSET_CONTENT_OK", strcmp(line, "relative-asset-v1") == 0);
    return orc_end();
}
