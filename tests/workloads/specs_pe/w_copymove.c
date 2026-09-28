/* CopyFileW, MoveFileW and MoveFileExW: the API installers and patchers actually
 * use, including the two refusals that make an atomic replace possible.
 *
 *   CopyFileW with bFailIfExists   -> ERROR_FILE_EXISTS, and the target is untouched
 *   CopyFileW without it           -> overwrites
 *   MoveFileW onto an existing name -> ERROR_ALREADY_EXISTS
 *   MoveFileExW with MOVEFILE_REPLACE_EXISTING -> succeeds, and the source is gone
 *   MoveFileW of an absent source  -> ERROR_FILE_NOT_FOUND
 *
 * The distinction between the two move failures is what a patcher branches on, and
 * a layer that answers ERROR_ACCESS_DENIED to both makes "is the target already
 * there?" and "is my source missing?" indistinguishable.
 */
#include "oracle_win.h"

static int write_file(const wchar_t *name, const char *text) {
    DWORD written = 0;
    HANDLE h = CreateFileW(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    WriteFile(h, text, (DWORD)strlen(text), &written, NULL);
    CloseHandle(h);
    return written == strlen(text);
}

static void read_into(const wchar_t *name, char *out, size_t n) {
    DWORD got = 0;
    HANDLE h = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    out[0] = 0;
    if (h == INVALID_HANDLE_VALUE) return;
    ReadFile(h, out, (DWORD)(n - 1), &got, NULL);
    out[got] = 0;
    CloseHandle(h);
}

int main(void) {
    char text[64];
    orc_begin("pe-fs-copy-and-move");

    DeleteFileW(L"src.dat");
    DeleteFileW(L"dst.dat");
    DeleteFileW(L"moved.dat");
    orc_check("WRITE_SOURCE", write_file(L"src.dat", "SOURCE-V1"));
    orc_check("WRITE_TARGET", write_file(L"dst.dat", "TARGET-V0"));

    SetLastError(0);
    orc_kv("COPY_FAIL_IF_EXISTS", "%s",
           CopyFileW(L"src.dat", L"dst.dat", TRUE) ? "copied" : "refused");
    orc_werr_now("COPY_FAIL_IF_EXISTS_ERROR");
    read_into(L"dst.dat", text, sizeof text);
    orc_kv("TARGET_AFTER_REFUSED_COPY", "%s", text);
    orc_check("REFUSED_COPY_LEFT_TARGET_ALONE", strcmp(text, "TARGET-V0") == 0);

    orc_check("COPY_OVERWRITING", CopyFileW(L"src.dat", L"dst.dat", FALSE) != 0);
    read_into(L"dst.dat", text, sizeof text);
    orc_kv("TARGET_AFTER_COPY", "%s", text);
    orc_check("COPY_REPLACED_THE_CONTENT", strcmp(text, "SOURCE-V1") == 0);
    orc_check("COPY_LEFT_SOURCE_IN_PLACE",
              GetFileAttributesW(L"src.dat") != INVALID_FILE_ATTRIBUTES);

    SetLastError(0);
    orc_kv("MOVE_ONTO_EXISTING", "%s",
           MoveFileW(L"src.dat", L"dst.dat") ? "moved" : "refused");
    orc_werr_now("MOVE_ONTO_EXISTING_ERROR");
    orc_check("REFUSED_MOVE_LEFT_SOURCE_IN_PLACE",
              GetFileAttributesW(L"src.dat") != INVALID_FILE_ATTRIBUTES);

    orc_check("WRITE_SOURCE_V2", write_file(L"src.dat", "SOURCE-V2"));
    orc_check("MOVE_EX_REPLACE_EXISTING",
              MoveFileExW(L"src.dat", L"dst.dat", MOVEFILE_REPLACE_EXISTING) != 0);
    read_into(L"dst.dat", text, sizeof text);
    orc_kv("TARGET_AFTER_REPLACE", "%s", text);
    orc_check("REPLACE_MOVED_THE_CONTENT", strcmp(text, "SOURCE-V2") == 0);
    orc_check("MOVE_CONSUMED_THE_SOURCE",
              GetFileAttributesW(L"src.dat") == INVALID_FILE_ATTRIBUTES);

    orc_check("PLAIN_MOVE_TO_A_FREE_NAME", MoveFileW(L"dst.dat", L"moved.dat") != 0);
    orc_check("OLD_NAME_GONE", GetFileAttributesW(L"dst.dat") == INVALID_FILE_ATTRIBUTES);
    read_into(L"moved.dat", text, sizeof text);
    orc_check("CONTENT_SURVIVED_THE_MOVE", strcmp(text, "SOURCE-V2") == 0);

    SetLastError(0);
    orc_kv("MOVE_ABSENT_SOURCE", "%s",
           MoveFileW(L"no-such-source.dat", L"whatever.dat") ? "moved" : "refused");
    orc_werr_now("MOVE_ABSENT_SOURCE_ERROR");

    SetLastError(0);
    orc_kv("COPY_ABSENT_SOURCE", "%s",
           CopyFileW(L"no-such-source.dat", L"whatever.dat", FALSE) ? "copied" : "refused");
    orc_werr_now("COPY_ABSENT_SOURCE_ERROR");

    orc_check("CLEANUP", DeleteFileW(L"moved.dat") != 0);
    return orc_end();
}
