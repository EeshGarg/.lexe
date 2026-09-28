/* Two DLLs with the SAME FILE NAME and different contents, built from this one
 * source with different -D values, so a specimen can say WHICH of them the loader
 * found. That is the only way to observe DLL search order for real: a test that
 * only checks "it loaded" cannot tell the application directory from a directory
 * added with SetDllDirectory.
 *
 * Built as out/dll/search-primary/wsearch.dll and out/dll/search-alt/wsearch.dll.
 */
#include <windows.h>

#define ORC_STR2(x) #x
#define ORC_STR(x) ORC_STR2(x)

__declspec(dllexport) const char *search_which(void) { return ORC_STR(WSEARCH_WHICH); }
__declspec(dllexport) int search_value(void) { return WSEARCH_VALUE; }

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)inst; (void)reserved; (void)reason;
    return TRUE;
}
