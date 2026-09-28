/* Five ways to die, one per mode, none of them a raise().
 *
 *   argv[1]  ill | fpe | bus | stack | assert
 *
 * The corpus already has a null-write SIGSEGV and an abort(). These are the
 * other death mechanisms a real program reaches, and they are NOT
 * interchangeable with each other: an illegal instruction, an integer division
 * by zero, a mapping whose backing file went away, a stack that ran out and a
 * failed assertion arrive through five different paths in the kernel and in
 * libc, and something that reports "the program crashed" for one of them may
 * report nothing at all for another.
 *
 * Every one of them is provoked genuinely -- a real faulting instruction, a real
 * truncated mapping, real recursion -- and never by sending the process a
 * signal, because a raise() proves only that raise() works.
 *
 * Undefined behaviour is the point here, so the optimiser is a real adversary:
 * an optimiser is entitled to delete a division by zero it can prove happens, or
 * to turn recursion into a loop that never overflows. `volatile` is what keeps
 * each fault reachable, and the compiler differentials in the generator are what
 * check that it stayed reachable at -O2 and -O3. A specimen that stops crashing
 * is a broken fixture, not a passing one.
 */
#include "oracle.h"

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* assert() must stay live regardless of the optimisation level. NDEBUG is never
 * defined by the generator's flag lists, but saying so explicitly means a future
 * flag cannot silently turn this specimen into a no-op. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

static volatile int v_zero = 0;
static volatile int v_one = 1;

/* Recursion the optimiser cannot flatten: each frame is volatile, is written to,
 * and its address is passed on, so no tail call and no frame elision. */
static unsigned long blow_the_stack(unsigned long depth, volatile char *below) {
    volatile char frame[4096];
    memset((void *)frame, (int)(depth & 0x7f), sizeof frame);
    frame[0] = (char)(below ? below[0] + 1 : 1);
    if (frame[4095] == (char)0xAB && depth == 0xFFFFFFFFul)
        return depth;                 /* never taken; defeats tail-call removal */
    return blow_the_stack(depth + 1, frame);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    orc_begin("linux-crash-modes");
    orc_kv("CRASH_MODE", "%s", mode);

    if (strcmp(mode, "ill") == 0) {
        orc_kv("FAULT_KIND", "illegal-instruction");
        orc_expect_death("sigill");
        /* __builtin_trap emits a genuine undefined instruction (ud2 on x86-64),
         * so the fault comes from the CPU and not from the C library. */
        __builtin_trap();
        orc_kv("UNREACHED", "yes");
        return 90;
    }
    if (strcmp(mode, "fpe") == 0) {
        volatile int q;
        orc_kv("FAULT_KIND", "integer-division-by-zero");
        orc_expect_death("sigfpe");
        q = v_one / v_zero;            /* both volatile: not foldable */
        orc_kv("UNREACHED", "%d", q);
        return 90;
    }
    if (strcmp(mode, "bus") == 0) {
        int fd;
        volatile char *p;
        char c;
        orc_kv("FAULT_KIND", "mapping-truncated-under-us");
        fd = open("bus.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || ftruncate(fd, 4096) != 0) {
            orc_kv("SETUP", "failed");
            orc_check("SETUP_OK", 0);
            return orc_end();
        }
        p = (volatile char *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                  MAP_SHARED, fd, 0);
        if (p == (volatile char *)MAP_FAILED) {
            orc_kv("SETUP", "mmap-failed");
            orc_check("SETUP_OK", 0);
            return orc_end();
        }
        c = p[0];                      /* the page exists at this point */
        orc_kv("FIRST_TOUCH_OK", "%d", (int)c == 0);
        /* Take the file out from under the mapping. Touching it now is a
         * SIGBUS: the address is mapped but there is no longer a page behind it. */
        if (ftruncate(fd, 0) != 0) {
            orc_kv("SETUP", "truncate-failed");
            orc_check("SETUP_OK", 0);
            return orc_end();
        }
        orc_check("SETUP_OK", 1);
        orc_expect_death("sigbus");
        p[0] = 'x';
        orc_kv("UNREACHED", "yes");
        return 90;
    }
    if (strcmp(mode, "stack") == 0) {
        orc_kv("FAULT_KIND", "stack-exhaustion");
        orc_expect_death("sigsegv-stack-guard");
        orc_kv("NOTE", "a guard-page fault, not a null dereference");
        (void)blow_the_stack(0, NULL);
        orc_kv("UNREACHED", "yes");
        return 90;
    }
    if (strcmp(mode, "assert") == 0) {
        orc_kv("FAULT_KIND", "failed-assertion");
        orc_expect_death("sigabrt-assert");
        /* Written through a volatile so the compiler cannot evaluate the
         * assertion at compile time and warn or fold it away. */
        assert(v_zero == v_one && "deliberate assertion failure");
        orc_kv("UNREACHED", "yes");
        return 90;
    }

    orc_kv("USAGE", "crash_modes ill|fpe|bus|stack|assert");
    orc_check("MODE_RECOGNISED", 0);
    return orc_end();
}
