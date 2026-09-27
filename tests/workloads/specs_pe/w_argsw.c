/* The WIDE view of the command line: GetCommandLineW plus CommandLineToArgvW.
 * This is what a Windows application actually sees, and it is where Unicode
 * arguments survive or do not. Reported as the hex of the UTF-8 encoding of each
 * wide argument, so every byte is accounted for. */
#include "oracle_win.h"
#include <shellapi.h>

int main(void) {
    int wargc = 0, i;
    LPWSTR *wargv;
    orc_begin("pe-arg-wide");
    wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    orc_check("COMMANDLINETOARGVW", wargv != NULL);
    if (!wargv) { orc_werr_now("LAST_ERROR"); return orc_end(); }
    orc_kv("WARGC", "%d", wargc);
    /* The whole command line contains the absolute path of the executable,
     * so its length is a property of where the corpus was built, not of the
     * program. Caught by comparing two generations in different output
     * directories. The individual arguments below are the real property. */
    orc_wide_obs("CMDLINE_TOTAL", GetCommandLineW());
    for (i = 1; i < wargc; i++) {
        char prefix[64];
        snprintf(prefix, sizeof prefix, "WARG_%d", i);
        orc_wide(prefix, wargv[i]);
    }
    LocalFree(wargv);
    orc_check("WIDE_ARGS_READ", 1);
    return orc_end();
}
