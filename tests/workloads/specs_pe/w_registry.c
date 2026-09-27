/* The Windows registry under HKEY_CURRENT_USER: create a key, write a string and
 * a DWORD, read both back, then delete the key. A translation layer that has no
 * registry at all, or a read-only one, reports itself here.
 *
 * Deliberately confined to a key of its own under Software, and it removes it. */
#include "oracle_win.h"

int main(void) {
    HKEY key;
    DWORD disp = 0, type = 0, size, value = 0;
    wchar_t sval[64];
    LONG rc;
    orc_begin("pe-registry-roundtrip");
    rc = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\LexeWorkload\\Probe", 0, NULL,
                         0, KEY_READ | KEY_WRITE, NULL, &key, &disp);
    orc_check("REG_CREATE", rc == ERROR_SUCCESS);
    if (rc != ERROR_SUCCESS) { orc_werr("REG_CREATE_ERROR", (unsigned long)rc); return orc_end(); }
    orc_kv("KEY_WAS_CREATED_NOT_OPENED", "%s", disp == REG_CREATED_NEW_KEY ? "yes" : "no");
    orc_check("SET_SZ", RegSetValueExW(key, L"Token", 0, REG_SZ,
                                      (const BYTE *)L"registry-token-1",
                                      (DWORD)((wcslen(L"registry-token-1") + 1) * 2))
              == ERROR_SUCCESS);
    value = 0xBEEF;
    orc_check("SET_DWORD", RegSetValueExW(key, L"Number", 0, REG_DWORD,
                                         (const BYTE *)&value, sizeof value) == ERROR_SUCCESS);
    size = sizeof sval;
    rc = RegQueryValueExW(key, L"Token", NULL, &type, (BYTE *)sval, &size);
    orc_check("QUERY_SZ", rc == ERROR_SUCCESS);
    orc_kv("SZ_TYPE_IS_REG_SZ", "%s", type == REG_SZ ? "yes" : "no");
    if (rc == ERROR_SUCCESS) orc_wide("SZ_VALUE", sval);
    value = 0;
    size = sizeof value;
    rc = RegQueryValueExW(key, L"Number", NULL, &type, (BYTE *)&value, &size);
    orc_check("QUERY_DWORD", rc == ERROR_SUCCESS);
    orc_kv("DWORD_TYPE_IS_REG_DWORD", "%s", type == REG_DWORD ? "yes" : "no");
    orc_kv("DWORD_VALUE", "%lu", (unsigned long)value);
    orc_check("DWORD_ROUNDTRIPPED", value == 0xBEEF);
    RegCloseKey(key);
    rc = RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\LexeWorkload\\Probe");
    orc_check("REG_DELETE", rc == ERROR_SUCCESS);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\LexeWorkload");
    return orc_end();
}
