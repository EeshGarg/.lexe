/* Thread-local storage, both ways Windows offers it at once:
 *
 *   the Win32 API   TlsAlloc / TlsSetValue / TlsGetValue, a slot the program asks
 *                   the OS for at runtime;
 *   the compiler     __thread, which needs a TLS directory in the PE image and is
 *                   set up by the loader before any of this code runs.
 *
 * Those are different mechanisms with different failure modes, and a runtime can
 * get one right and the other wrong. Four threads each write their own value
 * through both and read it back after a sleep long enough for the others to have
 * overwritten a shared slot, so a slot that is NOT per-thread shows up as a
 * mismatch rather than as a coincidence.
 */
#include "oracle_win.h"

static DWORD slot = TLS_OUT_OF_INDEXES;
static __thread int compiler_local = -1;
static volatile LONG api_ok = 0, compiler_ok = 0, started = 0;
static HANDLE go;

static DWORD WINAPI worker(LPVOID arg) {
    long id = (long)(LONG_PTR)arg;
    InterlockedIncrement(&started);
    /* Every thread writes before any thread reads: if the slot were shared, the
     * last writer would win and three of the four reads would be wrong. */
    TlsSetValue(slot, (LPVOID)(LONG_PTR)(id * 7 + 1));
    compiler_local = (int)(id * 13 + 5);
    WaitForSingleObject(go, 30000);
    if ((long)(LONG_PTR)TlsGetValue(slot) == id * 7 + 1) InterlockedIncrement(&api_ok);
    if (compiler_local == (int)(id * 13 + 5)) InterlockedIncrement(&compiler_ok);
    return 0;
}

int main(void) {
    HANDLE th[4];
    int i, made = 0;
    orc_begin("pe-tls");
    slot = TlsAlloc();
    orc_check("TLS_ALLOC", slot != TLS_OUT_OF_INDEXES);
    if (slot == TLS_OUT_OF_INDEXES) return orc_end();
    orc_obs("TLS_SLOT_INDEX", "%lu", (unsigned long)slot);

    /* The main thread's own slot must be untouched by the workers. */
    TlsSetValue(slot, (LPVOID)(LONG_PTR)999);
    compiler_local = 12345;

    go = CreateEventW(NULL, TRUE, FALSE, NULL);
    orc_check("BARRIER_EVENT", go != NULL);
    for (i = 0; i < 4; i++) {
        th[i] = CreateThread(NULL, 0, worker, (LPVOID)(LONG_PTR)i, 0, NULL);
        if (th[i]) made++;
    }
    orc_kv("THREADS_STARTED", "%d", made);
    /* Let every thread write before any of them reads. */
    while (started < made) Sleep(1);
    SetEvent(go);
    for (i = 0; i < made; i++) { WaitForSingleObject(th[i], 30000); CloseHandle(th[i]); }
    CloseHandle(go);

    orc_kv("TLS_API_PER_THREAD_OK", "%ld", (long)api_ok);
    orc_kv("COMPILER_TLS_PER_THREAD_OK", "%ld", (long)compiler_ok);
    orc_check("TLS_API_ISOLATED_ALL_THREADS", api_ok == 4);
    orc_check("COMPILER_TLS_ISOLATED_ALL_THREADS", compiler_ok == 4);
    orc_check("MAIN_TLS_API_UNTOUCHED", (long)(LONG_PTR)TlsGetValue(slot) == 999);
    orc_check("MAIN_COMPILER_TLS_UNTOUCHED", compiler_local == 12345);
    orc_check("TLS_FREE", TlsFree(slot) != 0);
    return orc_end();
}
