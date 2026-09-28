/* WaitForMultipleObjects, all three of its answers, with the state arranged so
 * each answer is the only possible one:
 *
 *   one object signalled  -> WAIT_OBJECT_0 + that object's INDEX, and the index
 *                            is the part a caller acts on
 *   nothing signalled     -> WAIT_TIMEOUT, and no object consumed
 *   everything signalled  -> WAIT_OBJECT_0 with bWaitAll
 *
 * It also checks the thing that is easy to get wrong in an emulation: with
 * bWaitAll FALSE and TWO objects signalled, the call must return the LOWEST index,
 * not an arbitrary one, and it must consume only that object -- so an
 * auto-reset event at a higher index is still signalled afterwards.
 */
#include "oracle_win.h"

#define N 4

int main(void) {
    HANDLE ev[N];
    int i;
    DWORD w;
    orc_begin("pe-sync-wait-multiple");
    for (i = 0; i < N; i++) ev[i] = CreateEventW(NULL, FALSE, FALSE, NULL);  /* auto-reset */
    for (i = 0; i < N; i++) if (!ev[i]) { orc_check("EVENTS_CREATED", 0); return orc_end(); }
    orc_check("EVENTS_CREATED", 1);
    orc_kv("OBJECT_COUNT", "%d", N);

    w = WaitForMultipleObjects(N, ev, FALSE, 150);
    orc_kv("WAIT_NONE_SIGNALLED", "%s", w == WAIT_TIMEOUT ? "timeout" : "other");
    orc_check("IDLE_WAIT_TIMED_OUT", w == WAIT_TIMEOUT);

    SetEvent(ev[2]);
    w = WaitForMultipleObjects(N, ev, FALSE, 5000);
    orc_kv("SIGNALLED_INDEX", "%ld",
           (w < WAIT_OBJECT_0 + N) ? (long)(w - WAIT_OBJECT_0) : -1L);
    orc_check("CORRECT_INDEX_REPORTED", w == WAIT_OBJECT_0 + 2);

    /* Two signalled at once: the lowest index wins and only it is consumed. */
    SetEvent(ev[1]);
    SetEvent(ev[3]);
    w = WaitForMultipleObjects(N, ev, FALSE, 5000);
    orc_kv("LOWEST_OF_TWO_INDEX", "%ld",
           (w < WAIT_OBJECT_0 + N) ? (long)(w - WAIT_OBJECT_0) : -1L);
    orc_check("LOWEST_INDEX_WINS", w == WAIT_OBJECT_0 + 1);
    w = WaitForSingleObject(ev[3], 0);
    orc_check("HIGHER_INDEX_NOT_CONSUMED", w == WAIT_OBJECT_0);

    for (i = 0; i < N; i++) SetEvent(ev[i]);
    w = WaitForMultipleObjects(N, ev, TRUE, 5000);
    orc_kv("WAIT_ALL", "%s", w == WAIT_OBJECT_0 ? "signalled" : "other");
    orc_check("WAIT_ALL_SUCCEEDED", w == WAIT_OBJECT_0);
    for (i = 0; i < N; i++)
        if (WaitForSingleObject(ev[i], 0) != WAIT_TIMEOUT) {
            orc_check("WAIT_ALL_CONSUMED_EVERY_OBJECT", 0);
            break;
        }
    if (i == N) orc_check("WAIT_ALL_CONSUMED_EVERY_OBJECT", 1);

    for (i = 0; i < N; i++) CloseHandle(ev[i]);
    return orc_end();
}
