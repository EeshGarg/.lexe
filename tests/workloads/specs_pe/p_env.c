/* Reports the named environment variables through the portable getenv, by
 * presence, byte length and hex. Which variables to look at come from argv. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    int i;
    orc_begin("pe-env-narrow");
    for (i = 1; i < argc; i++) {
        const char *v = getenv(argv[i]);
        char k[160];
        snprintf(k, sizeof k, "ENV_%s_PRESENT", argv[i]);
        orc_kv(k, "%s", v ? "yes" : "no");
        if (v) {
            size_t n = strlen(v);
            snprintf(k, sizeof k, "ENV_%s_LEN", argv[i]);
            orc_kv(k, "%lu", (unsigned long)n);
            snprintf(k, sizeof k, "ENV_%s_HEX", argv[i]);
            if (n <= 64) orc_hex(k, (const unsigned char *)v, n);
            else orc_kv(k, "(elided,%lu bytes)", (unsigned long)n);
        }
    }
    orc_check("READ_ENVIRONMENT", 1);
    return orc_end();
}
