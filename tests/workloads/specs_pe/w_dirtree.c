/* Builds a directory tree with CreateDirectoryW and walks it with
 * FindFirstFileW/FindNextFileW, reporting counts. The enumeration order of a
 * directory is not a contract, so only the counts are deterministic. */
#include "oracle_win.h"

static unsigned dirs = 0, files = 0;

static void walk(const wchar_t *path, int depth) {
    wchar_t pattern[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    if (depth > 6) return;
    _snwprintf(pattern, MAX_PATH, L"%s\\*", path);
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        wchar_t sub[MAX_PATH];
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        _snwprintf(sub, MAX_PATH, L"%s\\%s", path, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { dirs++; walk(sub, depth + 1); }
        else files++;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

int main(void) {
    int a, b, c;
    orc_begin("pe-fs-directory-tree");
    CreateDirectoryW(L"tree", NULL);
    for (a = 0; a < 2; a++) {
        wchar_t p1[MAX_PATH];
        _snwprintf(p1, MAX_PATH, L"tree\\a%d", a);
        CreateDirectoryW(p1, NULL);
        for (b = 0; b < 2; b++) {
            wchar_t p2[MAX_PATH];
            _snwprintf(p2, MAX_PATH, L"%s\\b%d", p1, b);
            CreateDirectoryW(p2, NULL);
            for (c = 0; c < 5; c++) {
                wchar_t p3[MAX_PATH];
                HANDLE h;
                DWORD w = 0;
                _snwprintf(p3, MAX_PATH, L"%s\\f%02d.dat", p2, c);
                h = CreateFileW(p3, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
                if (h != INVALID_HANDLE_VALUE) { WriteFile(h, "x", 1, &w, NULL); CloseHandle(h); }
            }
        }
    }
    walk(L"tree", 0);
    orc_kv("DIRS_FOUND", "%u", dirs);
    orc_kv("FILES_FOUND", "%u", files);
    orc_check("TREE_SHAPE", dirs == 6 && files == 20);
    return orc_end();
}
