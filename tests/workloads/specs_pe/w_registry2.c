/* The registry beyond a single round trip. argv[1] is the mode.
 *
 *   enum     three subkeys and three values under one key, counted with
 *            RegQueryInfoKeyW and then walked with RegEnumKeyExW and
 *            RegEnumValueW until ERROR_NO_MORE_ITEMS. Enumeration ORDER is not a
 *            contract, so the specimen checks the SET of names, not the sequence.
 *   types    REG_BINARY, REG_MULTI_SZ, REG_EXPAND_SZ and REG_QWORD written and
 *            read back with their types intact. A layer that collapses these into
 *            REG_SZ loses information real installers depend on.
 *   absent   the error paths: a key that is not there, a value that is not there,
 *            and deleting a key that is not there. Each must report
 *            ERROR_FILE_NOT_FOUND and the process must survive all three.
 *
 * The key name carries the mode and the process id, because one Wine prefix is
 * shared by every specimen running against that layer at the same time, and a
 * fixture that collides with another fixture is not measuring anything.
 */
#include "oracle_win.h"

static wchar_t keypath[256];

static void make_keypath(const char *mode) {
    wchar_t wmode[64];
    MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 64);
    _snwprintf(keypath, 256, L"Software\\LexeWorkload\\Reg2-%s-%lu",
               wmode, (unsigned long)GetCurrentProcessId());
}

static void nuke(void) {
    wchar_t sub[320];
    int i;
    for (i = 0; i < 3; i++) {
        _snwprintf(sub, 320, L"%s\\Sub%d", keypath, i);
        RegDeleteKeyW(HKEY_CURRENT_USER, sub);
    }
    RegDeleteKeyW(HKEY_CURRENT_USER, keypath);
}

static int do_enum(void) {
    HKEY key;
    DWORD i, subkeys = 0, values = 0, maxname = 0, maxvname = 0;
    int seen_sub[3] = {0, 0, 0}, seen_val[3] = {0, 0, 0};
    unsigned enum_subkeys = 0, enum_values = 0;
    LONG rc;

    rc = RegCreateKeyExW(HKEY_CURRENT_USER, keypath, 0, NULL, 0,
                         KEY_READ | KEY_WRITE, NULL, &key, NULL);
    orc_check("REG_CREATE", rc == ERROR_SUCCESS);
    if (rc != ERROR_SUCCESS) { orc_werr("REG_CREATE_ERROR", (unsigned long)rc); return 0; }
    for (i = 0; i < 3; i++) {
        wchar_t name[32];
        HKEY sub;
        DWORD v = 1000 + i;
        _snwprintf(name, 32, L"Sub%lu", (unsigned long)i);
        if (RegCreateKeyExW(key, name, 0, NULL, 0, KEY_READ | KEY_WRITE,
                            NULL, &sub, NULL) == ERROR_SUCCESS)
            RegCloseKey(sub);
        _snwprintf(name, 32, L"Val%lu", (unsigned long)i);
        RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE *)&v, sizeof v);
    }
    rc = RegQueryInfoKeyW(key, NULL, NULL, NULL, &subkeys, &maxname, NULL,
                          &values, &maxvname, NULL, NULL, NULL);
    orc_check("QUERY_INFO_KEY", rc == ERROR_SUCCESS);
    orc_kv("SUBKEY_COUNT", "%lu", (unsigned long)subkeys);
    orc_kv("VALUE_COUNT", "%lu", (unsigned long)values);

    for (i = 0;; i++) {
        wchar_t name[64];
        DWORD n = 64;
        rc = RegEnumKeyExW(key, i, name, &n, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) { orc_kv("ENUM_KEYS_ENDED", "no-more-items"); break; }
        if (rc != ERROR_SUCCESS) { orc_werr("ENUM_KEYS_ERROR", (unsigned long)rc); break; }
        enum_subkeys++;
        if (n == 4 && wcsncmp(name, L"Sub", 3) == 0 && name[3] >= L'0' && name[3] <= L'2')
            seen_sub[name[3] - L'0'] = 1;
        if (i > 16) break;
    }
    for (i = 0;; i++) {
        wchar_t name[64];
        DWORD n = 64, type = 0;
        rc = RegEnumValueW(key, i, name, &n, NULL, &type, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) { orc_kv("ENUM_VALUES_ENDED", "no-more-items"); break; }
        if (rc != ERROR_SUCCESS) { orc_werr("ENUM_VALUES_ERROR", (unsigned long)rc); break; }
        enum_values++;
        if (n == 4 && wcsncmp(name, L"Val", 3) == 0 && name[3] >= L'0' && name[3] <= L'2'
            && type == REG_DWORD)
            seen_val[name[3] - L'0'] = 1;
        if (i > 16) break;
    }
    orc_kv("ENUM_SUBKEYS_SEEN", "%u", enum_subkeys);
    orc_kv("ENUM_VALUES_SEEN", "%u", enum_values);
    orc_check("ALL_THREE_SUBKEY_NAMES_FOUND", seen_sub[0] && seen_sub[1] && seen_sub[2]);
    orc_check("ALL_THREE_VALUE_NAMES_FOUND", seen_val[0] && seen_val[1] && seen_val[2]);
    orc_check("SUBKEY_COUNT_MATCHES_WALK", subkeys == enum_subkeys);
    orc_check("VALUE_COUNT_MATCHES_WALK", values == enum_values);
    RegCloseKey(key);
    nuke();
    orc_check("CLEANED_UP",
              RegOpenKeyExW(HKEY_CURRENT_USER, keypath, 0, KEY_READ, &key)
              == ERROR_FILE_NOT_FOUND);
    return 1;
}

static int do_types(void) {
    static const unsigned char blob[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x7F, 0x80 };
    static const wchar_t multi[] = L"alpha\0beta\0gamma\0";
    HKEY key;
    LONG rc;
    DWORD type = 0, size;
    unsigned long long qword = 0;

    rc = RegCreateKeyExW(HKEY_CURRENT_USER, keypath, 0, NULL, 0,
                         KEY_READ | KEY_WRITE, NULL, &key, NULL);
    orc_check("REG_CREATE", rc == ERROR_SUCCESS);
    if (rc != ERROR_SUCCESS) { orc_werr("REG_CREATE_ERROR", (unsigned long)rc); return 0; }

    orc_check("SET_BINARY", RegSetValueExW(key, L"Blob", 0, REG_BINARY, blob,
                                           (DWORD)sizeof blob) == ERROR_SUCCESS);
    orc_check("SET_MULTI_SZ", RegSetValueExW(key, L"Many", 0, REG_MULTI_SZ,
                                             (const BYTE *)multi,
                                             (DWORD)sizeof multi) == ERROR_SUCCESS);
    orc_check("SET_EXPAND_SZ", RegSetValueExW(key, L"Expand", 0, REG_EXPAND_SZ,
                                              (const BYTE *)L"%LEXE_NOT_SET%\\tail",
                                              (DWORD)((wcslen(L"%LEXE_NOT_SET%\\tail") + 1) * 2))
              == ERROR_SUCCESS);
    qword = 0x0123456789ABCDEFULL;
    orc_check("SET_QWORD", RegSetValueExW(key, L"Big", 0, REG_QWORD,
                                          (const BYTE *)&qword, sizeof qword) == ERROR_SUCCESS);

    {
        unsigned char got[16];
        size = sizeof got;
        rc = RegQueryValueExW(key, L"Blob", NULL, &type, got, &size);
        orc_check("QUERY_BINARY", rc == ERROR_SUCCESS);
        orc_kv("BINARY_TYPE_IS_REG_BINARY", "%s", type == REG_BINARY ? "yes" : "no");
        orc_kv("BINARY_SIZE", "%lu", (unsigned long)size);
        if (rc == ERROR_SUCCESS) orc_hex("BINARY_HEX", got, size < 16 ? size : 16);
        orc_check("BINARY_ROUNDTRIPPED",
                  rc == ERROR_SUCCESS && size == sizeof blob
                  && memcmp(got, blob, sizeof blob) == 0);
    }
    {
        wchar_t got[64];
        unsigned strings = 0;
        const wchar_t *p;
        size = sizeof got;
        rc = RegQueryValueExW(key, L"Many", NULL, &type, (BYTE *)got, &size);
        orc_check("QUERY_MULTI_SZ", rc == ERROR_SUCCESS);
        orc_kv("MULTI_SZ_TYPE_IS_REG_MULTI_SZ", "%s", type == REG_MULTI_SZ ? "yes" : "no");
        if (rc == ERROR_SUCCESS) {
            for (p = got; *p; p += wcslen(p) + 1) { strings++; if (strings > 8) break; }
            orc_kv("MULTI_SZ_STRING_COUNT", "%u", strings);
            orc_check("MULTI_SZ_FIRST_IS_ALPHA", wcscmp(got, L"alpha") == 0);
        }
    }
    {
        wchar_t got[64];
        size = sizeof got;
        rc = RegQueryValueExW(key, L"Expand", NULL, &type, (BYTE *)got, &size);
        orc_check("QUERY_EXPAND_SZ", rc == ERROR_SUCCESS);
        orc_kv("EXPAND_SZ_TYPE_IS_REG_EXPAND_SZ", "%s", type == REG_EXPAND_SZ ? "yes" : "no");
        /* The point of REG_EXPAND_SZ is that the API does NOT expand it: the
         * unexpanded text comes back verbatim and expansion is the caller's job. */
        if (rc == ERROR_SUCCESS)
            orc_check("EXPAND_SZ_NOT_EXPANDED_BY_QUERY",
                      wcscmp(got, L"%LEXE_NOT_SET%\\tail") == 0);
    }
    {
        unsigned long long got = 0;
        size = sizeof got;
        rc = RegQueryValueExW(key, L"Big", NULL, &type, (BYTE *)&got, &size);
        orc_check("QUERY_QWORD", rc == ERROR_SUCCESS);
        orc_kv("QWORD_TYPE_IS_REG_QWORD", "%s", type == REG_QWORD ? "yes" : "no");
        orc_kv("QWORD_HEX", "%016llx", got);
        orc_check("QWORD_ROUNDTRIPPED", got == 0x0123456789ABCDEFULL);
    }
    RegCloseKey(key);
    nuke();
    orc_check("CLEANED_UP",
              RegOpenKeyExW(HKEY_CURRENT_USER, keypath, 0, KEY_READ, &key)
              == ERROR_FILE_NOT_FOUND);
    return 1;
}

static int do_absent(void) {
    HKEY key, live;
    LONG rc;
    DWORD type = 0, size = 4, junk = 0;

    rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\LexeWorkload\\NoSuchKeyAtAll",
                       0, KEY_READ, &key);
    orc_kv("OPEN_ABSENT_KEY", "%s", rc == ERROR_SUCCESS ? "ok" : "fail");
    orc_werr("OPEN_ABSENT_KEY_ERROR", (unsigned long)rc);
    orc_check("ABSENT_KEY_REPORTED", rc != ERROR_SUCCESS);

    rc = RegCreateKeyExW(HKEY_CURRENT_USER, keypath, 0, NULL, 0,
                         KEY_READ | KEY_WRITE, NULL, &live, NULL);
    orc_check("REG_CREATE", rc == ERROR_SUCCESS);
    if (rc != ERROR_SUCCESS) { orc_werr("REG_CREATE_ERROR", (unsigned long)rc); return 0; }
    rc = RegQueryValueExW(live, L"NoSuchValue", NULL, &type, (BYTE *)&junk, &size);
    orc_kv("QUERY_ABSENT_VALUE", "%s", rc == ERROR_SUCCESS ? "ok" : "fail");
    orc_werr("QUERY_ABSENT_VALUE_ERROR", (unsigned long)rc);

    /* A too-small buffer for a value that IS there is a different error again,
     * and a caller that cannot tell the two apart cannot grow its buffer. */
    {
        DWORD wide = 0x11223344;
        unsigned char tiny[2];
        RegSetValueExW(live, L"Present", 0, REG_DWORD, (const BYTE *)&wide, sizeof wide);
        size = sizeof tiny;
        rc = RegQueryValueExW(live, L"Present", NULL, &type, tiny, &size);
        orc_werr("QUERY_TOO_SMALL_ERROR", (unsigned long)rc);
        orc_kv("TOO_SMALL_REPORTS_REQUIRED_SIZE", "%s", size == sizeof wide ? "yes" : "no");
    }
    RegCloseKey(live);

    rc = RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\LexeWorkload\\NoSuchKeyAtAll");
    orc_kv("DELETE_ABSENT_KEY", "%s", rc == ERROR_SUCCESS ? "ok" : "fail");
    orc_werr("DELETE_ABSENT_KEY_ERROR", (unsigned long)rc);

    nuke();
    orc_check("SURVIVED_EVERY_ERROR_PATH", 1);
    return 1;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "enum";
    orc_begin("pe-registry-extended");
    orc_kv("REGISTRY_MODE", "%s", mode);
    make_keypath(mode);
    orc_wide_obs("KEY_PATH", keypath);
    nuke();
    if (strcmp(mode, "enum") == 0) do_enum();
    else if (strcmp(mode, "types") == 0) do_types();
    else if (strcmp(mode, "absent") == 0) do_absent();
    else { orc_kv("BAD_MODE", "%s", mode); orc_check("KNOWN_MODE", 0); }
    return orc_end();
}
