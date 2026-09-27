/* A versioned shared library: two implementations of the same symbol name under
 * different version nodes, with the newer one as the default. A consumer linked
 * against it records a versioned dependency, which is a real-world packaging
 * property that unversioned libraries do not exercise. */
int ver_value_v1(void) { return 11; }
int ver_value_v2(void) { return 22; }

__asm__(".symver ver_value_v1,ver_value@WL_1.0");
__asm__(".symver ver_value_v2,ver_value@@WL_2.0");
