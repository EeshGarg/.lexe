#include "leaf.h"

int leaf_depth(void) { return 3; }

/* The path is a literal, not something derived from __FILE__: __FILE__ contains
 * whatever the compiler was handed, which depends on the -I flags and the
 * working directory, and is therefore an observation rather than a fact about
 * the package. */
const char *leaf_path(void) { return "src/module/deep/leaf.c"; }
