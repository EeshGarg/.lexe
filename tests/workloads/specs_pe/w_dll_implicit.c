/* An implicit (link-time) import from a DLL that ships beside the executable.
 * When the DLL is present this reports its values; when it is absent the process
 * cannot start AT ALL -- there is no code in this file that can run to report
 * that, which is the whole point of the missing-DLL fixture. The evidence for
 * that case is the absence of an oracle file plus the loader's exit status. */
#include "oracle_win.h"

__declspec(dllimport) int lib_value(void);
__declspec(dllimport) const char *lib_name(void);
__declspec(dllimport) int lib_pointer_bits(void);

int main(void) {
    orc_begin("pe-dll-implicit");
    orc_kv("LIB_VALUE", "%d", lib_value());
    orc_kv("LIB_NAME", "%s", lib_name());
    orc_kv("LIB_POINTER_BITS", "%d", lib_pointer_bits());
    orc_check("IMPORT_RESOLVED", lib_value() == 1234);
    orc_check("DLLMAIN_RAN", GetFileAttributesA("dllmain.log") != INVALID_FILE_ATTRIBUTES);
    return orc_end();
}
