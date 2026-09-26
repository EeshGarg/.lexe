/* Deliberately a DLL, declared as the entrypoint of a `windows` package.
 *
 * A DLL is a perfectly valid PE image. It is not a program — nothing can execute
 * it as one — so "is this a runnable Windows executable?" is a different question
 * from "is this a PE?". See ../README.md. */
#include <windows.h>

__declspec(dllexport) int lexe_broken_example(void) { return 0; }

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
