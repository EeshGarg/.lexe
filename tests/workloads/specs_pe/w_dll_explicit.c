/* LoadLibraryW plus GetProcAddress at runtime. argv[1] is the library to load and
 * argv[2] says whether it is expected to load, so one binary covers the DLL that
 * is there, the DLL that is missing, and the DLL built for the wrong
 * architecture. A failure to load is reported symbolically and the specimen still
 * exits cleanly: refusing to load a bad DLL is correct behaviour, not a crash. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    wchar_t wname[512];
    HMODULE h;
    int expect_ok;
    orc_begin("pe-dll-explicit");
    if (argc < 3) { orc_kv("USAGE", "w_dll_explicit <dll> <ok|fail>"); return 2; }
    expect_ok = (strcmp(argv[2], "ok") == 0);
    orc_kv("EXPECTATION", "%s", expect_ok ? "ok" : "fail");
    MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wname, 512);
    SetLastError(0);
    h = LoadLibraryW(wname);
    orc_kv("LOADLIBRARY", "%s", h ? "ok" : "fail");
    if (!h) {
        orc_werr_now("LOAD_ERROR");
        orc_check("OUTCOME_AS_DECLARED", !expect_ok);
        return orc_end();
    }
    orc_check("OUTCOME_AS_DECLARED", expect_ok);
    {
        int (*value)(void) = (int (*)(void))(void *)GetProcAddress(h, "lib_value");
        int (*bits)(void) = (int (*)(void))(void *)GetProcAddress(h, "lib_pointer_bits");
        orc_check("GETPROCADDRESS_VALUE", value != NULL);
        orc_check("GETPROCADDRESS_BITS", bits != NULL);
        if (value) orc_kv("LIB_VALUE", "%d", value());
        if (bits) orc_kv("LIB_POINTER_BITS", "%d", bits());
        orc_check("MISSING_SYMBOL_REPORTS_NULL", GetProcAddress(h, "no_such_export") == NULL);
    }
    orc_check("FREE_LIBRARY", FreeLibrary(h) != 0);
    return orc_end();
}
