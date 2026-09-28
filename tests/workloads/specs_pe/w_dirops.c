/* Directory operations and their error paths, which w_dirtree.c (a happy-path
 * walk) does not reach:
 *
 *   CreateDirectoryW on a name that already exists -> ERROR_ALREADY_EXISTS
 *   CreateDirectoryW with a missing parent         -> ERROR_PATH_NOT_FOUND
 *   RemoveDirectoryW on a directory with content   -> ERROR_DIR_NOT_EMPTY
 *   RemoveDirectoryW on a FILE                     -> refused, with its own error
 *   DeleteFileW on a DIRECTORY                     -> refused, with its own error
 *   SetCurrentDirectoryW and back
 *
 * The three "wrong kind of object" errors are the interesting ones: they are how an
 * uninstaller decides whether something it is about to remove is a file or a
 * directory, and a layer that answers ERROR_ACCESS_DENIED to all of them makes
 * that undecidable.
 */
#include "oracle_win.h"

int main(void) {
    wchar_t back[MAX_PATH];
    DWORD written = 0;
    HANDLE h;
    orc_begin("pe-fs-directory-operations");

    DeleteFileW(L"dirops\\inside.dat");
    RemoveDirectoryW(L"dirops\\nested");
    RemoveDirectoryW(L"dirops");

    orc_check("CREATE_DIRECTORY", CreateDirectoryW(L"dirops", NULL) != 0);
    orc_check("IS_A_DIRECTORY",
              (GetFileAttributesW(L"dirops") & FILE_ATTRIBUTE_DIRECTORY) != 0);

    SetLastError(0);
    orc_kv("CREATE_EXISTING_DIRECTORY", "%s",
           CreateDirectoryW(L"dirops", NULL) ? "created" : "refused");
    orc_werr_now("CREATE_EXISTING_DIRECTORY_ERROR");

    SetLastError(0);
    orc_kv("CREATE_WITH_MISSING_PARENT", "%s",
           CreateDirectoryW(L"dirops\\absent\\deeper", NULL) ? "created" : "refused");
    orc_werr_now("CREATE_WITH_MISSING_PARENT_ERROR");

    orc_check("CREATE_NESTED", CreateDirectoryW(L"dirops\\nested", NULL) != 0);
    h = CreateFileW(L"dirops\\inside.dat", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("CREATE_FILE_INSIDE", h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) { WriteFile(h, "in", 2, &written, NULL); CloseHandle(h); }

    SetLastError(0);
    orc_kv("REMOVE_NON_EMPTY_DIRECTORY", "%s",
           RemoveDirectoryW(L"dirops") ? "removed" : "refused");
    orc_werr_now("REMOVE_NON_EMPTY_DIRECTORY_ERROR");

    SetLastError(0);
    orc_kv("REMOVE_DIRECTORY_ON_A_FILE", "%s",
           RemoveDirectoryW(L"dirops\\inside.dat") ? "removed" : "refused");
    orc_werr_now("REMOVE_DIRECTORY_ON_A_FILE_ERROR");

    SetLastError(0);
    orc_kv("DELETE_FILE_ON_A_DIRECTORY", "%s",
           DeleteFileW(L"dirops\\nested") ? "deleted" : "refused");
    orc_werr_now("DELETE_FILE_ON_A_DIRECTORY_ERROR");

    /* Change into it, prove it, and come back. The paths themselves are
     * environment-dependent, so only the relationship between them is checked. */
    orc_check("GET_CURRENT_DIRECTORY", GetCurrentDirectoryW(MAX_PATH, back) > 0);
    orc_check("SET_CURRENT_DIRECTORY", SetCurrentDirectoryW(L"dirops\\nested") != 0);
    {
        wchar_t now[MAX_PATH];
        size_t n = GetCurrentDirectoryW(MAX_PATH, now);
        orc_wide_obs("CWD_INSIDE", now);
        orc_check("CWD_ENDS_IN_NESTED",
                  n > 7 && wcscmp(now + n - 7, L"\\nested") == 0);
        /* A relative name now resolves against the NEW working directory. */
        orc_kv("PARENT_FILE_VISIBLE_FROM_CHILD_DIR", "%s",
               GetFileAttributesW(L"inside.dat") != INVALID_FILE_ATTRIBUTES ? "yes" : "no");
        orc_kv("PARENT_FILE_VISIBLE_VIA_DOTDOT", "%s",
               GetFileAttributesW(L"..\\inside.dat") != INVALID_FILE_ATTRIBUTES ? "yes" : "no");
    }
    orc_check("RETURN_TO_ORIGINAL_DIRECTORY", SetCurrentDirectoryW(back) != 0);

    orc_check("DELETE_INSIDE_FILE", DeleteFileW(L"dirops\\inside.dat") != 0);
    orc_check("REMOVE_NESTED", RemoveDirectoryW(L"dirops\\nested") != 0);
    orc_check("REMOVE_NOW_EMPTY_DIRECTORY", RemoveDirectoryW(L"dirops") != 0);
    orc_check("DIRECTORY_GONE",
              GetFileAttributesW(L"dirops") == INVALID_FILE_ATTRIBUTES);
    return orc_end();
}
