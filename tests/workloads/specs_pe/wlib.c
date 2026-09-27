/* The DLL the loader specimens load: implicitly, explicitly, and in the wrong
 * architecture. Built for both x86-64 and i686 from this one source. */
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) int lib_value(void) { return 1234; }
__declspec(dllexport) const char *lib_name(void) { return "lexe-workload-dll"; }
__declspec(dllexport) int lib_pointer_bits(void) { return (int)(sizeof(void *) * 8); }

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        /* Evidence that DllMain ran, on a separate line the specimen can check. */
        FILE *f = fopen("dllmain.log", "a");
        if (f) { fprintf(f, "DLLMAIN_PROCESS_ATTACH=yes\n"); fclose(f); }
    }
    return TRUE;
}
