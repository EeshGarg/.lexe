/* Translation unit 3 of 4: the oracle. Only this unit does I/O, so a link that
 * drops it produces a program that runs and prints nothing -- which is exactly
 * the failure a corpus needs to be able to tell apart from a program that was
 * never launched. */
#include <stdarg.h>
#include <stdio.h>
#include "common.h"

static int failures = 0;

void report_kv(const char *key, const char *fmt, ...) {
    va_list ap;
    printf("%s=", key);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

void report_check(const char *key, int ok) {
    printf("%s=%s\n", key, ok ? "yes" : "no");
    if (!ok) failures++;
}

int report_failures(void) { return failures; }
