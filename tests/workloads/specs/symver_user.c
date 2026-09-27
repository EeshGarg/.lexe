/* Links against the versioned library and reports the value it resolved to,
 * which must be the WL_2.0 default. The id comes from the environment because two
 * specimens share this source: the absolute-RUNPATH one and its $ORIGIN-relative
 * twin, and a fixture that printed the wrong id would be a fixture that lies. */
#include "oracle.h"
#include <unistd.h>

extern int ver_value(void);

int main(void) {
    const char *id = getenv("FIXTURE_ID");
    orc_begin(id ? id : "linux-link-symbol-versioning");
    orc_kv("VER_VALUE", "%d", ver_value());
    orc_check("RESOLVED_TO_DEFAULT_V2", ver_value() == 22);
    return orc_end();
}
