/* Portable file work: create, write, read back, rename, delete, and confirm the
 * deletion. The same source runs natively and translated, so a difference is a
 * difference in the filesystem view, not in the program. */
#include "oracle_win.h"

int main(void) {
    FILE *f;
    char buf[128];
    const char *payload = "portable-file-payload-v1\n";
    orc_begin("pe-fs-portable-file");
    f = fopen("work.tmp", "wb");
    orc_check("CREATE", f != NULL);
    if (!f) return orc_end();
    orc_check("WRITE", fwrite(payload, 1, strlen(payload), f) == strlen(payload));
    fclose(f);
    f = fopen("work.tmp", "rb");
    orc_check("REOPEN", f != NULL);
    if (f) {
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        buf[n] = 0;
        fclose(f);
        orc_kv("READ_BYTES", "%lu", (unsigned long)n);
        orc_check("CONTENT_MATCHES", strcmp(buf, payload) == 0);
    }
    remove("work.final");
    orc_check("RENAME", rename("work.tmp", "work.final") == 0);
    orc_check("OLD_NAME_GONE", fopen("work.tmp", "rb") == NULL);
    orc_check("NEW_NAME_PRESENT", (f = fopen("work.final", "rb")) != NULL);
    if (f) fclose(f);
    orc_check("DELETE", remove("work.final") == 0);
    orc_check("DELETED", fopen("work.final", "rb") == NULL);
    return orc_end();
}
