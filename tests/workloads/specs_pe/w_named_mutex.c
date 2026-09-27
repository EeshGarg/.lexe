/* Named kernel objects: a named mutex, taken twice. The second CreateMutexW must
 * report ERROR_ALREADY_EXISTS while still returning a usable handle, and the
 * mutex must actually serialise, which a thread verifies by trying to take it
 * while the main thread holds it. The name includes the process id so parallel
 * runs of this corpus cannot collide. */
#include "oracle_win.h"

static wchar_t mutex_name[128];
static volatile LONG probe_result = -1;

static DWORD WINAPI prober(LPVOID unused) {
    HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, mutex_name);
    (void)unused;
    if (!m) { probe_result = 100; return 0; }
    probe_result = (WaitForSingleObject(m, 0) == WAIT_TIMEOUT) ? 0 : 1;
    CloseHandle(m);
    return 0;
}

int main(void) {
    HANDLE first, second, th;
    orc_begin("pe-sync-named-mutex");
    _snwprintf(mutex_name, 128, L"Local\\LexeWorkloadMutex-%lu",
               (unsigned long)GetCurrentProcessId());
    first = CreateMutexW(NULL, TRUE, mutex_name);
    orc_check("CREATE_FIRST", first != NULL);
    if (!first) { orc_werr_now("CREATE_ERROR"); return orc_end(); }
    orc_kv("FIRST_WAS_NEW", "%s", GetLastError() == ERROR_ALREADY_EXISTS ? "no" : "yes");
    second = CreateMutexW(NULL, FALSE, mutex_name);
    orc_check("CREATE_SECOND_HANDLE", second != NULL);
    orc_kv("SECOND_REPORTS_ALREADY_EXISTS", "%s",
           GetLastError() == ERROR_ALREADY_EXISTS ? "yes" : "no");
    th = CreateThread(NULL, 0, prober, NULL, 0, NULL);
    orc_check("PROBE_THREAD", th != NULL);
    if (th) { WaitForSingleObject(th, 30000); CloseHandle(th); }
    orc_kv("PROBE_RESULT", "%ld", (long)probe_result);
    orc_check("MUTEX_SERIALISED", probe_result == 0);
    ReleaseMutex(first);
    if (second) CloseHandle(second);
    CloseHandle(first);
    return orc_end();
}
