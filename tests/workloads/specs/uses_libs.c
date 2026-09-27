/* Links three shared libraries built alongside it, where gamma -> beta -> alpha.
 * Used unchanged for the LD_LIBRARY_PATH, RPATH, RUNPATH and $ORIGIN variants:
 * only the link line and the on-disk layout differ, and the program reports
 * where the dynamic loader actually found things. */
#include "oracle.h"
#include <link.h>
#include <unistd.h>

extern int alpha_value(void);
extern int beta_value(void);
extern int gamma_value(void);

static int count_objects(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (info->dlpi_name && info->dlpi_name[0]) {
        orc_obs("DSO", "%s", info->dlpi_name);
        (*(int *)data)++;
    }
    return 0;
}

int main(void) {
    int n = 0;
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-link-shared");
    orc_kv("ALPHA", "%d", alpha_value());
    orc_kv("BETA", "%d", beta_value());
    orc_kv("GAMMA", "%d", gamma_value());
    dl_iterate_phdr(count_objects, &n);
    orc_obs("DSO_COUNT", "%d", n);
    orc_check("CHAIN_CONSISTENT", gamma_value() == (alpha_value() + 7) * 2);
    return orc_end();
}
