/* The Interlocked family: eight threads hammering three different atomic
 * primitives, with exact totals.
 *
 * These totals are not statistical. If an Interlocked operation is not atomic --
 * because a translation layer, or a compiler, lowered it to something that is not
 * -- the totals come out LOW, and by how much is the race. That makes this one of
 * the few specimens in the corpus where an exact number is a real correctness
 * claim rather than a description.
 *
 *   INCREMENT_TOTAL  8 threads x 50000 InterlockedIncrement            -> 400000
 *   ADD_TOTAL        8 threads x 50000 InterlockedExchangeAdd of 3     -> 1200000
 *   CAS_TOTAL        8 threads x 50000 increments of a value guarded by
 *                    an InterlockedCompareExchange spin lock           -> 400000
 *
 * Deliberately 32-bit LONG throughout, so the same source is meaningful in a
 * 32-bit process where the 64-bit interlocked entry points are not.
 */
#include "oracle_win.h"

#define THREADS 8
#define ITERS 50000

static volatile LONG counter = 0;
static volatile LONG adder = 0;
static volatile LONG spin = 0;
static LONG guarded = 0;          /* only ever touched while `spin` is held */
static volatile LONG exchanges = 0;

static DWORD WINAPI worker(LPVOID unused) {
    int i;
    (void)unused;
    for (i = 0; i < ITERS; i++) {
        InterlockedIncrement(&counter);
        InterlockedExchangeAdd(&adder, 3);
        while (InterlockedCompareExchange(&spin, 1, 0) != 0) { /* spin */ }
        guarded++;
        InterlockedExchange(&spin, 0);
        InterlockedIncrement(&exchanges);
    }
    return 0;
}

int main(void) {
    HANDLE th[THREADS];
    int i, made = 0;
    orc_begin("pe-sync-interlocked");
    orc_kv("THREADS", "%d", THREADS);
    orc_kv("ITERATIONS_EACH", "%d", ITERS);
    for (i = 0; i < THREADS; i++) {
        th[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (th[i]) made++;
    }
    orc_kv("THREADS_STARTED", "%d", made);
    for (i = 0; i < made; i++) { WaitForSingleObject(th[i], 120000); CloseHandle(th[i]); }

    orc_kv("INCREMENT_TOTAL", "%ld", (long)counter);
    orc_kv("ADD_TOTAL", "%ld", (long)adder);
    orc_kv("CAS_GUARDED_TOTAL", "%ld", (long)guarded);
    orc_kv("EXCHANGE_COUNT", "%ld", (long)exchanges);
    orc_kv("SPIN_LOCK_RELEASED", "%ld", (long)spin);
    orc_check("ALL_THREADS_STARTED", made == THREADS);
    orc_check("INCREMENT_WAS_ATOMIC", counter == (LONG)THREADS * ITERS);
    orc_check("EXCHANGE_ADD_WAS_ATOMIC", adder == (LONG)THREADS * ITERS * 3);
    orc_check("COMPARE_EXCHANGE_MUTUAL_EXCLUSION", guarded == (LONG)THREADS * ITERS);
    orc_check("LOCK_NOT_LEFT_HELD", spin == 0);
    return orc_end();
}
