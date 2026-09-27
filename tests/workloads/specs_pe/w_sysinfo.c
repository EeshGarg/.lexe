/* What the layer says it is. Everything here is an OBSERVATION by design: these
 * values legitimately differ between Wine and Proton and between Proton versions,
 * and a consumer must never treat a difference as a failure. It exists so that
 * when two layers disagree about something else, this record says which two
 * Windows they each claimed to be. */
#include "oracle_win.h"

int main(void) {
    SYSTEM_INFO si;
    wchar_t buf[256];
    DWORD n;
    orc_begin("pe-layer-identity");
    GetSystemInfo(&si);
    orc_obs("PROCESSOR_ARCHITECTURE", "%u", (unsigned)si.wProcessorArchitecture);
    orc_obs("PAGE_SIZE", "%lu", (unsigned long)si.dwPageSize);
    orc_obs("NUMBER_OF_PROCESSORS", "%lu", (unsigned long)si.dwNumberOfProcessors);
    {
        HMODULE k = GetModuleHandleW(L"kernel32.dll");
        typedef void (WINAPI *GVER)(LPOSVERSIONINFOEXW);
        orc_obs("KERNEL32_PRESENT", "%s", k ? "yes" : "no");
        (void)(GVER)0;
    }
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const char *(*wgv)(void) = NULL;
        if (ntdll) wgv = (const char *(*)(void))(void *)GetProcAddress(ntdll, "wine_get_version");
        orc_obs("WINE_GET_VERSION_PRESENT", "%s", wgv ? "yes" : "no");
        if (wgv) orc_obs("WINE_VERSION", "%s", wgv());
    }
    n = GetEnvironmentVariableW(L"STEAM_COMPAT_DATA_PATH", buf, 256);
    orc_obs("STEAM_COMPAT_DATA_PATH_SET", "%s", n > 0 ? "yes" : "no");
    n = GetEnvironmentVariableW(L"WINEPREFIX", buf, 256);
    orc_obs("WINEPREFIX_SET", "%s", n > 0 ? "yes" : "no");
    orc_check("IDENTITY_REPORTED", 1);
    return orc_end();
}
