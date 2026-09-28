#ifndef PORTABLE_MIXED_CPART_H
#define PORTABLE_MIXED_CPART_H
/* The extern "C" guard is the whole subject of this recipe: without it the C++
 * translation unit asks the linker for a mangled name that the C translation
 * unit never defined, and the build fails at the link step with a diagnostic
 * that mentions a symbol nobody wrote. */
#ifdef __cplusplus
extern "C" {
#endif

int  cpart_value(void);
const char *cpart_language(void);
unsigned long cpart_mix(unsigned long seed, int rounds);

#ifdef __cplusplus
}
#endif
#endif
