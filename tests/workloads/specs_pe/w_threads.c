/* Win32 threads (not pthreads): CreateThread, a critical section,
 * WaitForMultipleObjects. argv[1] is the thread count. The sum is
 * order-independent, so the report is deterministic however they are scheduled. */
#include "oracle_win.h"

static long long total = 0;
static CRITICAL_SECTION lock;

static DWORD WINAPI worker(LPVOID arg) {
    long id = (long)(LONG_PTR)arg, acc = 0, i;
    for (i = 0; i < 20000; i++) acc += (id * 31 + i) % 97;
    EnterCriticalSection(&lock);
    total += acc;
    LeaveCriticalSection(&lock);
    return 0;
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 4, i;
    HANDLE *h;
    long started = 0;
    orc_begin("pe-proc-threads");
    if (n < 1 || n > 512) { orc_kv("BAD_ARG", "%ld", n); return 2; }
    InitializeCriticalSection(&lock);
    h = (HANDLE *)calloc((size_t)n, sizeof *h);
    orc_kv("THREADS_REQUESTED", "%ld", n);
    for (i = 0; i < n; i++) {
        h[i] = CreateThread(NULL, 0, worker, (LPVOID)(LONG_PTR)i, 0, NULL);
        if (!h[i]) break;
        started++;
    }
    /* WaitForMultipleObjects takes at most 64 handles, so wait in batches. */
    for (i = 0; i < started; i += 64) {
        DWORD count = (DWORD)((started - i) < 64 ? (started - i) : 64);
        WaitForMultipleObjects(count, &h[i], TRUE, 60000);
    }
    for (i = 0; i < started; i++) CloseHandle(h[i]);
    orc_kv("THREADS_STARTED", "%ld", started);
    orc_kv("TOTAL", "%lld", total);
    orc_check("ALL_THREADS_STARTED", started == n);
    DeleteCriticalSection(&lock);
    free(h);
    return orc_end();
}
