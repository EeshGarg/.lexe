/* A counting semaphore, checked deterministically rather than statistically.
 *
 * Testing a semaphore by starting N threads and seeing how many got in at once is
 * a race dressed up as a test. This does it the other way round: the main thread
 * drains the semaphore itself, so the state is known exactly at every step, and a
 * probe thread reports what a zero-timeout wait sees at each of those states.
 *
 *   count 2 -> take 1 -> take 2 -> probe must TIME OUT (the semaphore is empty)
 *           -> release 1, previous count must be reported as 0
 *           -> probe must ACQUIRE
 *           -> release past the maximum must FAIL with ERROR_TOO_MANY_POSTS
 */
#include "oracle_win.h"

static wchar_t sem_name[128];
static volatile LONG probe_outcome = -1;

static DWORD WINAPI prober(LPVOID unused) {
    HANDLE s = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, sem_name);
    DWORD w;
    (void)unused;
    if (!s) { probe_outcome = 100; return 0; }
    w = WaitForSingleObject(s, 0);
    probe_outcome = (w == WAIT_TIMEOUT) ? 0 : (w == WAIT_OBJECT_0) ? 1 : 2;
    if (w == WAIT_OBJECT_0) ReleaseSemaphore(s, 1, NULL);
    CloseHandle(s);
    return 0;
}

static long run_probe(void) {
    HANDLE th;
    probe_outcome = -1;
    th = CreateThread(NULL, 0, prober, NULL, 0, NULL);
    if (!th) return -2;
    WaitForSingleObject(th, 30000);
    CloseHandle(th);
    return (long)probe_outcome;
}

int main(void) {
    HANDLE sem;
    LONG previous = -1;
    orc_begin("pe-sync-semaphore");
    _snwprintf(sem_name, 128, L"Local\\LexeWorkloadSem-%lu",
               (unsigned long)GetCurrentProcessId());
    sem = CreateSemaphoreW(NULL, 2, 2, sem_name);
    orc_check("CREATE_SEMAPHORE", sem != NULL);
    if (!sem) { orc_werr_now("CREATE_ERROR"); return orc_end(); }
    orc_kv("INITIAL_COUNT", "2");
    orc_kv("MAXIMUM_COUNT", "2");

    orc_check("TAKE_FIRST", WaitForSingleObject(sem, 5000) == WAIT_OBJECT_0);
    orc_check("TAKE_SECOND", WaitForSingleObject(sem, 5000) == WAIT_OBJECT_0);

    orc_kv("PROBE_WHEN_EMPTY", "%ld", run_probe());
    orc_check("EMPTY_SEMAPHORE_BLOCKS", probe_outcome == 0);

    orc_check("RELEASE_ONE", ReleaseSemaphore(sem, 1, &previous) != 0);
    orc_kv("PREVIOUS_COUNT_REPORTED", "%ld", (long)previous);
    orc_check("PREVIOUS_COUNT_WAS_ZERO", previous == 0);

    orc_kv("PROBE_AFTER_RELEASE", "%ld", run_probe());
    orc_check("RELEASED_SEMAPHORE_ADMITS_ONE", probe_outcome == 1);

    /* The probe put its slot back, so the count is 1 and the maximum is 2:
     * releasing two more must be refused, and refused with a distinct error. */
    SetLastError(0);
    orc_kv("RELEASE_PAST_MAXIMUM", "%s",
           ReleaseSemaphore(sem, 2, NULL) != 0 ? "accepted" : "refused");
    orc_werr_now("RELEASE_PAST_MAXIMUM_ERROR");

    /* Opening the same name a second time must reach the SAME object. */
    {
        HANDLE again = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, sem_name);
        orc_check("OPEN_BY_NAME", again != NULL);
        if (again) {
            orc_check("NAMED_OBJECT_IS_SHARED",
                      WaitForSingleObject(again, 5000) == WAIT_OBJECT_0);
            ReleaseSemaphore(again, 1, NULL);
            CloseHandle(again);
        }
    }
    CloseHandle(sem);
    return orc_end();
}
