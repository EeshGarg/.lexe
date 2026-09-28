/* DLL search order, observed rather than assumed. argv[1] is the mode.
 *
 * Two DLLs called wsearch.dll exist, with different contents: the "primary" one
 * (search_value 1111) is staged beside the executable when the mode needs it, and
 * the "alt" one (search_value 2222) is always staged in an altdir\ subdirectory of
 * the executable's own directory. Because search_which() says which one answered,
 * the specimen can distinguish the application directory from a directory the
 * program added at runtime -- which a test that only checked "LoadLibrary
 * succeeded" could not.
 *
 *   appdir           both present. The application directory must win.
 *   needs-setdll     only altdir has it. The first LoadLibraryW must FAIL; after
 *                    SetDllDirectoryW(altdir) the same call must succeed and
 *                    report the alt DLL. The change in outcome is the evidence
 *                    that SetDllDirectory did something.
 *   explicit-abs     only altdir has it, loaded by absolute path, no search at all.
 *   adddlldirectory  only altdir has it, reached through the modern
 *                    SetDefaultDllDirectories + AddDllDirectory pair. Those two
 *                    entry points do not exist on every Windows, so whether they
 *                    are present is an OBSERVATION and the outcome is declared as
 *                    one of two legitimate possibilities.
 *
 * All paths are built from GetModuleFileNameW, not from the working directory,
 * because that is what real software does and because the working directory is
 * not a property of the program.
 */
#include "oracle_win.h"

typedef BOOL (WINAPI *SETDEFDIRS)(DWORD);
typedef void * (WINAPI *ADDDLLDIR)(PCWSTR);

#ifndef LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
#  define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS 0x00001000
#endif

static wchar_t moddir[MAX_PATH];
static wchar_t altdir[MAX_PATH];
static wchar_t altdll[MAX_PATH];

static int module_dir(void) {
    wchar_t self[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, self, MAX_PATH);
    size_t i, cut = 0;
    if (len == 0) return 0;
    for (i = 0; i < len; i++) if (self[i] == L'\\' || self[i] == L'/') cut = i;
    self[cut] = 0;
    wcscpy(moddir, self);
    _snwprintf(altdir, MAX_PATH, L"%s\\altdir", moddir);
    _snwprintf(altdll, MAX_PATH, L"%s\\altdir\\wsearch.dll", moddir);
    return 1;
}

/* Report which DLL answered, through its own exports. */
static void report(HMODULE h, const char *prefix) {
    char key[128];
    const char *(*which)(void) = (const char *(*)(void))(void *)GetProcAddress(h, "search_which");
    int (*value)(void) = (int (*)(void))(void *)GetProcAddress(h, "search_value");
    snprintf(key, sizeof key, "%s_WHICH", prefix);
    orc_kv(key, "%s", which ? which() : "(no-export)");
    snprintf(key, sizeof key, "%s_VALUE", prefix);
    orc_kv(key, "%d", value ? value() : -1);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "appdir";
    HMODULE h;
    orc_begin("pe-dll-search-order");
    orc_kv("SEARCH_MODE", "%s", mode);
    orc_check("MODULE_DIR_FOUND", module_dir());
    orc_obs("ALTDIR", "%s", "see ALTDIR_LEN");
    orc_wide_obs("ALTDIR_PATH", altdir);
    orc_check("ALT_DLL_IS_STAGED",
              GetFileAttributesW(altdll) != INVALID_FILE_ATTRIBUTES);

    if (strcmp(mode, "appdir") == 0) {
        SetLastError(0);
        h = LoadLibraryW(L"wsearch.dll");
        orc_kv("LOAD", "%s", h ? "ok" : "fail");
        orc_check("LOADED", h != NULL);
        if (!h) { orc_werr_now("LOAD_ERROR"); return orc_end(); }
        report(h, "LOADED");
        orc_check("APPLICATION_DIRECTORY_WON", 1);
        FreeLibrary(h);
    } else if (strcmp(mode, "needs-setdll") == 0) {
        SetLastError(0);
        h = LoadLibraryW(L"wsearch.dll");
        orc_kv("FIRST_LOAD", "%s", h ? "ok" : "fail");
        if (h) {
            /* Not what this mode is for: say so loudly rather than quietly. */
            report(h, "FIRST");
            orc_check("FIRST_LOAD_FAILED_AS_DECLARED", 0);
            FreeLibrary(h);
        } else {
            orc_werr_now("FIRST_LOAD_ERROR");
            orc_check("FIRST_LOAD_FAILED_AS_DECLARED", 1);
        }
        orc_check("SETDLLDIRECTORY", SetDllDirectoryW(altdir) != 0);
        SetLastError(0);
        h = LoadLibraryW(L"wsearch.dll");
        orc_kv("SECOND_LOAD", "%s", h ? "ok" : "fail");
        orc_check("SECOND_LOAD_SUCCEEDED", h != NULL);
        if (!h) { orc_werr_now("SECOND_LOAD_ERROR"); return orc_end(); }
        report(h, "LOADED");
        orc_kv("SETDLLDIRECTORY_CHANGED_THE_OUTCOME", "yes");
        FreeLibrary(h);
        SetDllDirectoryW(NULL);
    } else if (strcmp(mode, "explicit-abs") == 0) {
        SetLastError(0);
        h = LoadLibraryW(altdll);
        orc_kv("LOAD", "%s", h ? "ok" : "fail");
        orc_check("LOADED", h != NULL);
        if (!h) { orc_werr_now("LOAD_ERROR"); return orc_end(); }
        report(h, "LOADED");
        orc_kv("NO_SEARCH_PERFORMED", "yes");
        FreeLibrary(h);
    } else if (strcmp(mode, "adddlldirectory") == 0) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        SETDEFDIRS set_def = NULL;
        ADDDLLDIR add_dir = NULL;
        if (k32) {
            set_def = (SETDEFDIRS)(void *)GetProcAddress(k32, "SetDefaultDllDirectories");
            add_dir = (ADDDLLDIR)(void *)GetProcAddress(k32, "AddDllDirectory");
        }
        orc_obs("SETDEFAULTDLLDIRECTORIES_PRESENT", "%s", set_def ? "yes" : "no");
        orc_obs("ADDDLLDIRECTORY_PRESENT", "%s", add_dir ? "yes" : "no");
        orc_kv("MODERN_SEARCH_API_PRESENT", "%s", (set_def && add_dir) ? "yes" : "no");
        if (set_def && add_dir) {
            orc_check("SET_DEFAULT_DIRS", set_def(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) != 0);
            orc_check("ADD_DLL_DIRECTORY", add_dir(altdir) != NULL);
            SetLastError(0);
            h = LoadLibraryW(L"wsearch.dll");
            orc_kv("LOAD", "%s", h ? "ok" : "fail");
            orc_check("LOADED", h != NULL);
            if (!h) { orc_werr_now("LOAD_ERROR"); return orc_end(); }
            report(h, "LOADED");
            FreeLibrary(h);
        } else {
            orc_kv("LOAD", "not-attempted");
        }
        orc_check("MODERN_SEARCH_API_PROBED", 1);
    } else {
        orc_kv("BAD_MODE", "%s", mode);
        orc_check("KNOWN_MODE", 0);
    }
    return orc_end();
}
