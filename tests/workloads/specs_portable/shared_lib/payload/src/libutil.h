#ifndef PORTABLE_LIBUTIL_H
#define PORTABLE_LIBUTIL_H
int  util_value(void);
const char *util_build_id(void);
unsigned long util_mix(unsigned long seed, int rounds);
#endif
