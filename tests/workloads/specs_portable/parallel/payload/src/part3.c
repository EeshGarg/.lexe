/* Part 3 of four, deliberately independent of the other three so make may
 * compile them in any order or all at once. The ANSWER must not depend on the
 * order, which is the property a parallel build is being asked about. */
#include "parts.h"

unsigned long part3(unsigned long x) {
    int i;
    for (i = 0; i < 4096; i++) {
        x = (x * 16777619UL + 3UL + (unsigned long)i) & 0xffffffffUL;
        x ^= x >> 13;
    }
    return x;
}
