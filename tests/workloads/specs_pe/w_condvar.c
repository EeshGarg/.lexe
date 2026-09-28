/* SRWLOCK and CONDITION_VARIABLE: the Vista-era synchronisation primitives, which
 * are not kernel objects with handles but structures the runtime manipulates in
 * the process's own memory. That makes them a completely different implementation
 * path from CreateMutex and CreateEvent, and one a translation layer has to
 * provide itself.
 *
 * A bounded producer/consumer over a 4-slot ring: the producer blocks on a
 * "not full" condition, the consumer on a "not empty" one, and the queue is
 * smaller than the item count so both directions must actually block. The totals
 * are exact -- 100 items, 0..99, sum 4950 -- so a lost wakeup shows up as a
 * missing item and not as a slow run.
 *
 * It also exercises the reader side: after the handoff, four threads take the
 * SRWLOCK SHARED at once and all of them must get in.
 */
#include "oracle_win.h"

#define CAP 4
#define ITEMS 100

static SRWLOCK lock;
static CONDITION_VARIABLE not_full, not_empty;
static int ring[CAP];
static int head = 0, tail = 0, count = 0;
static long produced = 0, consumed = 0, consumed_sum = 0;
static int producer_blocked = 0, consumer_blocked = 0;

static DWORD WINAPI producer(LPVOID unused) {
    int i;
    (void)unused;
    for (i = 0; i < ITEMS; i++) {
        AcquireSRWLockExclusive(&lock);
        while (count == CAP) {
            producer_blocked = 1;
            SleepConditionVariableSRW(&not_full, &lock, INFINITE, 0);
        }
        ring[tail] = i;
        tail = (tail + 1) % CAP;
        count++;
        produced++;
        ReleaseSRWLockExclusive(&lock);
        WakeConditionVariable(&not_empty);
        /* After the first few items the producer paces itself, which GUARANTEES
         * the consumer runs the ring dry and has to block. Without this the
         * blocking claim below would be a race that usually happened to pass,
         * which is exactly the kind of fixture this corpus refuses to ship. */
        if (i >= 8) Sleep(2);
    }
    return 0;
}

static volatile LONG readers_in = 0, readers_ok = 0;

static DWORD WINAPI reader(LPVOID unused) {
    (void)unused;
    AcquireSRWLockShared(&lock);
    InterlockedIncrement(&readers_in);
    /* Every reader holds the shared lock at the same time, so if the shared mode
     * were really exclusive, readers_in would never reach 4 and this would time
     * out rather than pass. */
    {
        int spins = 0;
        while (readers_in < 4 && spins < 5000) { Sleep(1); spins++; }
    }
    if (readers_in >= 4) InterlockedIncrement(&readers_ok);
    ReleaseSRWLockShared(&lock);
    return 0;
}

int main(void) {
    HANDLE th, rd[4];
    int i, made = 0;
    orc_begin("pe-sync-condition-variable");
    InitializeSRWLock(&lock);
    InitializeConditionVariable(&not_full);
    InitializeConditionVariable(&not_empty);
    orc_kv("RING_CAPACITY", "%d", CAP);
    orc_kv("ITEMS", "%d", ITEMS);

    th = CreateThread(NULL, 0, producer, NULL, 0, NULL);
    orc_check("PRODUCER_THREAD", th != NULL);
    if (!th) return orc_end();

    /* Let the producer fill the ring completely before the first consume, which
     * GUARANTEES the producer has to block on the not-full condition. */
    Sleep(150);
    for (i = 0; i < ITEMS; i++) {
        int value;
        AcquireSRWLockExclusive(&lock);
        while (count == 0) {
            consumer_blocked = 1;
            SleepConditionVariableSRW(&not_empty, &lock, INFINITE, 0);
        }
        value = ring[head];
        head = (head + 1) % CAP;
        count--;
        consumed++;
        consumed_sum += value;
        ReleaseSRWLockExclusive(&lock);
        WakeConditionVariable(&not_full);
    }
    WaitForSingleObject(th, 60000);
    CloseHandle(th);

    orc_kv("PRODUCED", "%ld", produced);
    orc_kv("CONSUMED", "%ld", consumed);
    orc_kv("CONSUMED_SUM", "%ld", consumed_sum);
    orc_kv("RING_DRAINED", "%d", count);
    orc_check("EVERY_ITEM_PRODUCED", produced == ITEMS);
    orc_check("EVERY_ITEM_CONSUMED", consumed == ITEMS);
    orc_check("NO_ITEM_LOST_OR_DUPLICATED", consumed_sum == (long)ITEMS * (ITEMS - 1) / 2);
    orc_check("RING_EMPTY_AT_END", count == 0);
    /* The queue is smaller than the item count, so both sides MUST have blocked
     * at least once. If neither did, the condition variables were never used and
     * the exact totals above would prove much less than they look. */
    orc_check("PRODUCER_REALLY_BLOCKED", producer_blocked == 1);
    orc_check("CONSUMER_REALLY_BLOCKED", consumer_blocked == 1);

    for (i = 0; i < 4; i++) {
        rd[i] = CreateThread(NULL, 0, reader, NULL, 0, NULL);
        if (rd[i]) made++;
    }
    for (i = 0; i < made; i++) { WaitForSingleObject(rd[i], 60000); CloseHandle(rd[i]); }
    orc_kv("SHARED_READERS_CONCURRENT", "%ld", (long)readers_ok);
    orc_check("SRWLOCK_SHARED_ADMITS_ALL_FOUR", readers_ok == 4);
    return orc_end();
}
