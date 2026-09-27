/* Links against the versioned library and reports the value it resolved to,
 * which must be the WL_2.0 default. */
#include "oracle.h"
#include <unistd.h>

extern int ver_value(void);

int main(void) {
    orc_begin("linux-link-symbol-versioning");
    orc_kv("VER_VALUE", "%d", ver_value());
    orc_check("RESOLVED_TO_DEFAULT_V2", ver_value() == 22);
    return orc_end();
}
