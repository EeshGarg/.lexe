/* Translation unit 2 of 4: depends on util.c. If a build system gets the link
 * order or the object list wrong, this is the unresolved symbol. */
#include "common.h"

unsigned long calc_series(int n) {
    unsigned long acc = 0;
    int i;
    for (i = 1; i <= n; i++) acc = (acc + util_mix((unsigned long)i, 16)) & 0xffffffffUL;
    return acc;
}
