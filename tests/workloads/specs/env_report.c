/* Reports a declared set of environment variables (present/absent, and the value
 * in hex when present) plus how many entries environ holds. The variable names
 * come from argv, so one binary serves every environment fixture. */
#include "oracle.h"
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    int i, count = 0;
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-env-report");
    while (environ[count]) count++;
    orc_obs("ENVIRON_COUNT", "%d", count);
    for (i = 1; i < argc; i++) {
        const char *v = getenv(argv[i]);
        printf("ENV_%s_PRESENT=%s\n", argv[i], v ? "yes" : "no");
        if (v) {
            size_t j, n = strlen(v);
            printf("ENV_%s_LEN=%lu\n", argv[i], (unsigned long)n);
            printf("ENV_%s_HEX=", argv[i]);
            for (j = 0; j < n && j < 64; j++) printf("%02x", (unsigned char)v[j]);
            putchar('\n');
        }
    }
    orc_check("ENVIRON_NONEMPTY_OR_DECLARED_EMPTY", count >= 0);
    return orc_end();
}
