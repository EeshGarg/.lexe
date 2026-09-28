/* The PE RESOURCE directory: an executable reading data out of its own image.
 *
 * Nothing else in this corpus produces a .rsrc section, and almost every real
 * Windows program has one. Three separate mechanisms read it here, and they go
 * through different code:
 *
 *   FindResourceW / SizeofResource / LoadResource / LockResource  -- raw RCDATA
 *   LoadStringW                                                    -- the string table
 *   GetFileVersionInfoW / VerQueryValueW                           -- the version block,
 *      read back OUT OF THE FILE ON DISK rather than out of the loaded image, which
 *      is a different path again and the one installers use
 *
 * The RCDATA blob is sixteen bytes written out in w_resource.rc, so its content and
 * its hash are properties of that file and were known before anything ran:
 *   01 23 45 67 89 ab cd ef 32 10 76 54 66 98 ba dc
 */
#include "oracle_win.h"
#include <winver.h>

int main(void) {
    HRSRC found;
    HGLOBAL loaded;
    const unsigned char *bytes;
    DWORD size;
    wchar_t str[128];
    int n;
    orc_begin("pe-format-resources");

    found = FindResourceW(NULL, L"BLOB", (LPCWSTR)RT_RCDATA);
    orc_check("FIND_RESOURCE_RCDATA", found != NULL);
    if (!found) { orc_werr_now("FIND_RESOURCE_ERROR"); return orc_end(); }
    size = SizeofResource(NULL, found);
    orc_kv("RCDATA_SIZE", "%lu", (unsigned long)size);
    loaded = LoadResource(NULL, found);
    orc_check("LOAD_RESOURCE", loaded != NULL);
    bytes = (const unsigned char *)LockResource(loaded);
    orc_check("LOCK_RESOURCE", bytes != NULL);
    if (bytes && size >= 16) {
        orc_hex("RCDATA_HEX", bytes, 16);
        orc_kv("RCDATA_HASH", "%016llx", orc_fnv1a(bytes, 16));
        orc_check("RCDATA_CONTENT_AS_AUTHORED",
                  bytes[0] == 0x01 && bytes[1] == 0x23 && bytes[14] == 0xba
                  && bytes[15] == 0xdc);
    }
    orc_check("RCDATA_SIZE_IS_SIXTEEN", size == 16);

    str[0] = 0;
    n = LoadStringW(GetModuleHandleW(NULL), 101, str, 128);
    orc_kv("LOAD_STRING_LENGTH", "%d", n);
    orc_check("LOAD_STRING", n > 0);
    if (n > 0) orc_wide("STRING_101", str);
    orc_check("STRING_101_AS_AUTHORED", wcscmp(str, L"lexe-workload-resource-string") == 0);
    str[0] = 0;
    n = LoadStringW(GetModuleHandleW(NULL), 102, str, 128);
    orc_check("STRING_102_AS_AUTHORED", n > 0 && wcscmp(str, L"second-string") == 0);
    /* A string id that was never authored must return 0, not stale memory. */
    str[0] = 0;
    orc_kv("ABSENT_STRING_LENGTH", "%d", LoadStringW(GetModuleHandleW(NULL), 999, str, 128));

    orc_check("VERSION_RESOURCE_PRESENT",
              FindResourceW(NULL, (LPCWSTR)1, (LPCWSTR)RT_VERSION) != NULL);

    /* The version block read out of the file on disk. */
    {
        wchar_t self[MAX_PATH];
        DWORD handle = 0, len;
        if (GetModuleFileNameW(NULL, self, MAX_PATH) == 0) {
            orc_check("SELF_PATH", 0);
            return orc_end();
        }
        len = GetFileVersionInfoSizeW(self, &handle);
        orc_check("GET_FILE_VERSION_INFO_SIZE", len > 0);
        if (len > 0 && len < 65536) {
            void *buf = malloc(len);
            if (buf && GetFileVersionInfoW(self, handle, len, buf)) {
                VS_FIXEDFILEINFO *ffi = NULL;
                UINT flen = 0;
                orc_check("GET_FILE_VERSION_INFO", 1);
                if (VerQueryValueW(buf, L"\\", (LPVOID *)&ffi, &flen) && ffi) {
                    orc_kv("FILE_VERSION_MS", "0x%08lx", (unsigned long)ffi->dwFileVersionMS);
                    orc_kv("FILE_VERSION_LS", "0x%08lx", (unsigned long)ffi->dwFileVersionLS);
                    orc_kv("FILE_VERSION", "%lu.%lu.%lu.%lu",
                           (unsigned long)(ffi->dwFileVersionMS >> 16),
                           (unsigned long)(ffi->dwFileVersionMS & 0xFFFF),
                           (unsigned long)(ffi->dwFileVersionLS >> 16),
                           (unsigned long)(ffi->dwFileVersionLS & 0xFFFF));
                    orc_check("FILE_VERSION_AS_AUTHORED",
                              ffi->dwFileVersionMS == 0x00030001u
                              && ffi->dwFileVersionLS == 0x00040001u);
                } else {
                    orc_check("VER_QUERY_VALUE_ROOT", 0);
                }
                {
                    wchar_t *product = NULL;
                    UINT plen = 0;
                    if (VerQueryValueW(buf, L"\\StringFileInfo\\040904b0\\ProductName",
                                       (LPVOID *)&product, &plen) && product) {
                        orc_wide("PRODUCT_NAME", product);
                        orc_check("PRODUCT_NAME_AS_AUTHORED",
                                  wcscmp(product, L"lexe-workload-resource") == 0);
                    } else {
                        orc_check("VER_QUERY_STRING_BLOCK", 0);
                    }
                }
            } else {
                orc_check("GET_FILE_VERSION_INFO", 0);
            }
            free(buf);
        }
    }
    return orc_end();
}
