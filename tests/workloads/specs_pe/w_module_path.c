/* GetModuleFileNameW against argv[0]: the PE analogue of comparing argv[0] with
 * /proc/self/exe. A launcher that copies, renames or rewrites the command line
 * changes one of these and not the other. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    wchar_t path[MAX_PATH];
    DWORD n;
    orc_begin("pe-interface-module-path");
    n = GetModuleFileNameW(NULL, path, MAX_PATH);
    orc_check("GET_MODULE_FILE_NAME", n > 0);
    if (n > 0) orc_obs("MODULE_PATH_LEN", "%lu", (unsigned long)n);
    orc_obs("ARGV0", "%s", argc > 0 ? argv[0] : "(none)");
    orc_kv("MODULE_PATH_IS_ABSOLUTE", "%s",
           (n > 2 && path[1] == L':' && path[2] == L'\\') ? "yes" : "no");
    orc_kv("MODULE_PATH_ENDS_IN_EXE", "%s",
           (n > 4 && path[n-4] == L'.') ? "yes" : "no");
    orc_check("HAVE_BOTH_VIEWS", n > 0 && argc > 0);
    return orc_end();
}
