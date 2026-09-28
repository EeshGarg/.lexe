#ifndef PORTABLE_MULTI_EXEC_COMMON_H
#define PORTABLE_MULTI_EXEC_COMMON_H
/* Shared by all three programs, so the package really is one build with one
 * dependency graph rather than three packages in a trench coat. */
unsigned long mix(unsigned long seed, int rounds);
void emit_common(const char *program, const char *fallback_id);
#endif
