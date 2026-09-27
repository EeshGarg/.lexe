/* Shared declarations for the four-translation-unit recipe. The point of the
 * specimen is that a portable build is not always one compiler invocation: it
 * has a dependency graph, object files, and an ordering that a build system has
 * to get right on a machine the publisher never saw. */
#ifndef PORTABLE_MULTI_COMMON_H
#define PORTABLE_MULTI_COMMON_H

/* util.c */
unsigned long util_mix(unsigned long seed, int rounds);
const char *util_isa(void);

/* calc.c -- deliberately depends on util.c, so link order matters */
unsigned long calc_series(int n);

/* report.c -- the only thing that prints */
void report_kv(const char *key, const char *fmt, ...);
void report_check(const char *key, int ok);
int report_failures(void);

#endif
