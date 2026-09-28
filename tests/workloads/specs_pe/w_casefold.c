/* Windows filenames are CASE-INSENSITIVE but CASE-PRESERVING. That is not true of
 * the Linux filesystem a translation layer is usually sitting on, so the layer has
 * to do the folding itself -- and an application that writes "Save.DAT" and reads
 * "save.dat" (as a great deal of Windows software does) works or does not work
 * depending entirely on whether it did.
 *
 *   created as MixedCase.TXT
 *   opened as mixedcase.txt        -> must succeed
 *   opened as MIXEDCASE.TXT        -> must succeed
 *   found by the pattern MIXED*.*  -> must be found
 *   the name reported by FindFirstFileW -> must still be MixedCase.TXT
 *
 * The last one is the case-PRESERVING half, and it is the one a naive
 * lowercase-everything implementation gets wrong.
 */
#include "oracle_win.h"

static int open_named(const wchar_t *name) {
    HANDLE h = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    CloseHandle(h);
    return 1;
}

int main(void) {
    HANDLE h;
    DWORD written = 0;
    WIN32_FIND_DATAW fd;
    HANDLE find;
    orc_begin("pe-fs-case-insensitive");

    DeleteFileW(L"MixedCase.TXT");
    DeleteFileW(L"mixedcase.txt");
    h = CreateFileW(L"MixedCase.TXT", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("CREATE_MIXED_CASE", h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) { orc_werr_now("CREATE_ERROR"); return orc_end(); }
    WriteFile(h, "case-payload", 12, &written, NULL);
    CloseHandle(h);

    SetLastError(0);
    orc_kv("OPEN_ALL_LOWER", "%s", open_named(L"mixedcase.txt") ? "opened" : "refused");
    orc_check("LOWERCASE_NAME_RESOLVED", open_named(L"mixedcase.txt"));
    SetLastError(0);
    orc_kv("OPEN_ALL_UPPER", "%s", open_named(L"MIXEDCASE.TXT") ? "opened" : "refused");
    orc_check("UPPERCASE_NAME_RESOLVED", open_named(L"MIXEDCASE.TXT"));
    orc_check("EXACT_NAME_RESOLVED", open_named(L"MixedCase.TXT"));

    find = FindFirstFileW(L"MIXED*.*", &fd);
    orc_check("FOUND_BY_UPPERCASE_PATTERN", find != INVALID_HANDLE_VALUE);
    if (find != INVALID_HANDLE_VALUE) {
        orc_wide("FOUND_NAME", fd.cFileName);
        orc_check("CASE_WAS_PRESERVED_ON_DISK", wcscmp(fd.cFileName, L"MixedCase.TXT") == 0);
        FindClose(find);
    }

    /* Attributes, deletion and creation must all fold the same way; a layer that
     * folds in CreateFile but not in GetFileAttributes is a real failure mode. */
    orc_kv("ATTRS_BY_LOWER_NAME", "%s",
           GetFileAttributesW(L"mixedcase.txt") != INVALID_FILE_ATTRIBUTES ? "found" : "absent");
    orc_check("ATTRIBUTES_FOLDED_TOO",
              GetFileAttributesW(L"mixedcase.txt") != INVALID_FILE_ATTRIBUTES);

    /* Creating the "other case" must hit the SAME file, not make a second one. */
    h = CreateFileW(L"MIXEDCASE.TXT", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("CREATE_ALWAYS_OTHER_CASE", h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) { WriteFile(h, "second", 6, &written, NULL); CloseHandle(h); }
    {
        unsigned found = 0;
        find = FindFirstFileW(L"*.TXT", &fd);
        if (find != INVALID_HANDLE_VALUE) {
            do { found++; } while (FindNextFileW(find, &fd) && found < 16);
            FindClose(find);
        }
        orc_kv("TXT_FILES_PRESENT", "%u", found);
        orc_check("NO_SECOND_FILE_WAS_CREATED", found == 1);
    }

    orc_check("DELETE_BY_LOWER_NAME", DeleteFileW(L"mixedcase.txt") != 0);
    orc_check("GONE", GetFileAttributesW(L"MixedCase.TXT") == INVALID_FILE_ATTRIBUTES);
    return orc_end();
}
