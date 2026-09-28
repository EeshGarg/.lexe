/* Memory-mapped files and named section objects. Games map their asset archives
 * rather than reading them, and a mapping is the one file API where the data path
 * bypasses ReadFile entirely -- so a layer can have perfect ReadFile behaviour and
 * still get this wrong.
 *
 * Three things are checked, each with a different failure signature:
 *   1. a write THROUGH the mapping must appear in the file on disk when read back
 *      with ordinary ReadFile, which proves the view and the file are the same
 *      bytes and not a copy;
 *   2. a second, READ-ONLY view of the same file must see those bytes;
 *   3. a NAMED pagefile-backed section opened twice by name must be one object:
 *      a write through the first view must be visible through the second.
 *
 * Offsets used here are into the specimen's own data file, which never carries
 * FIXTURE_ID, so they are properties of the program.
 */
#include "oracle_win.h"

#define SIZE 4096

static const wchar_t *NAME = L"mapped.dat";

int main(void) {
    HANDLE file, mapping;
    unsigned char *view;
    unsigned i;
    unsigned long long expect_hash;
    orc_begin("pe-fs-memory-mapped-file");

    DeleteFileW(NAME);
    file = CreateFileW(NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("CREATE_FILE", file != INVALID_HANDLE_VALUE);
    if (file == INVALID_HANDLE_VALUE) { orc_werr_now("CREATE_ERROR"); return orc_end(); }

    mapping = CreateFileMappingW(file, NULL, PAGE_READWRITE, 0, SIZE, NULL);
    orc_check("CREATE_FILE_MAPPING", mapping != NULL);
    if (!mapping) { orc_werr_now("MAPPING_ERROR"); CloseHandle(file); return orc_end(); }
    orc_kv("MAPPING_SIZE", "%d", SIZE);

    view = (unsigned char *)MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, SIZE);
    orc_check("MAP_VIEW_OF_FILE", view != NULL);
    if (!view) { orc_werr_now("MAP_VIEW_ERROR"); return orc_end(); }

    for (i = 0; i < SIZE; i++) view[i] = (unsigned char)((i * 17u + 3u) & 0xFF);
    expect_hash = orc_fnv1a(view, SIZE);
    orc_kv("VIEW_HASH", "%016llx", expect_hash);
    orc_check("FLUSH_VIEW", FlushViewOfFile(view, SIZE) != 0);
    orc_check("UNMAP_VIEW", UnmapViewOfFile(view) != 0);

    /* Read-only second view of the SAME mapping object. */
    view = (unsigned char *)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, SIZE);
    orc_check("MAP_VIEW_READ_ONLY", view != NULL);
    if (view) {
        orc_kv("READ_ONLY_VIEW_HASH", "%016llx", orc_fnv1a(view, SIZE));
        orc_check("READ_ONLY_VIEW_SEES_THE_WRITES",
                  orc_fnv1a(view, SIZE) == expect_hash);
        UnmapViewOfFile(view);
    }
    CloseHandle(mapping);

    /* ReadFile must see exactly the same bytes: the mapping was not a private copy. */
    {
        unsigned char buf[SIZE];
        DWORD got = 0;
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        orc_check("SEEK_TO_START", SetFilePointerEx(file, zero, NULL, FILE_BEGIN) != 0);
        orc_check("READ_FILE", ReadFile(file, buf, SIZE, &got, NULL) != 0);
        orc_kv("READ_BYTES", "%lu", (unsigned long)got);
        orc_kv("FILE_HASH", "%016llx", orc_fnv1a(buf, got));
        orc_check("FILE_ON_DISK_MATCHES_THE_VIEW",
                  got == SIZE && orc_fnv1a(buf, got) == expect_hash);
    }
    CloseHandle(file);

    /* A NAMED, pagefile-backed section: two handles by name, one object. */
    {
        wchar_t secname[128];
        HANDLE a, b;
        unsigned char *va, *vb;
        _snwprintf(secname, 128, L"Local\\LexeWorkloadSection-%lu",
                   (unsigned long)GetCurrentProcessId());
        a = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 256, secname);
        orc_check("CREATE_NAMED_SECTION", a != NULL);
        SetLastError(0);
        b = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, secname);
        orc_check("OPEN_NAMED_SECTION_BY_NAME", b != NULL);
        if (a && b) {
            va = (unsigned char *)MapViewOfFile(a, FILE_MAP_WRITE, 0, 0, 256);
            vb = (unsigned char *)MapViewOfFile(b, FILE_MAP_READ, 0, 0, 256);
            orc_check("BOTH_VIEWS_MAPPED", va != NULL && vb != NULL);
            if (va && vb) {
                memcpy(va, "SHARED-SECTION-PAYLOAD", 23);
                orc_check("SECOND_HANDLE_SEES_THE_SAME_MEMORY",
                          memcmp(vb, "SHARED-SECTION-PAYLOAD", 23) == 0);
                UnmapViewOfFile(va);
                UnmapViewOfFile(vb);
            }
        }
        if (a) CloseHandle(a);
        if (b) CloseHandle(b);
        SetLastError(0);
        orc_kv("OPEN_ABSENT_SECTION", "%s",
               OpenFileMappingW(FILE_MAP_READ, FALSE, L"Local\\LexeNoSuchSectionEver")
               ? "opened" : "refused");
        orc_werr_now("OPEN_ABSENT_SECTION_ERROR");
    }

    orc_check("DELETE_MAPPED_FILE", DeleteFileW(NAME) != 0);
    return orc_end();
}
