/* A large anonymous mapping (1 GiB reserved), touched sparsely one byte per
 * page-group so the resident set stays small while the address space does not.
 * Reports whether the reservation succeeded and what stopped it if not. */
#include "oracle.h"
#include <sys/mman.h>
#include <unistd.h>

#define GIB (1024UL * 1024UL * 1024UL)
#define STRIDE (16UL * 1024UL * 1024UL)

int main(void) {
    unsigned char *m;
    unsigned long i, touched = 0, sum = 0;
    orc_begin("linux-fs-mmap-large-anon");
    orc_kv("RESERVE_BYTES", "%lu", GIB);
    m = (unsigned char *)mmap(NULL, GIB, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (m == MAP_FAILED) {
        orc_kv("MMAP", "fail");
        orc_kv("MMAP_ERRNO", "%s", orc_errno_name(errno));
        orc_check("LARGE_MAP_AVAILABLE", 0);
        return orc_end();
    }
    orc_kv("MMAP", "ok");
    for (i = 0; i < GIB; i += STRIDE) {
        m[i] = (unsigned char)((i / STRIDE) & 0xff);
        touched++;
    }
    for (i = 0; i < GIB; i += STRIDE) sum += m[i];
    orc_kv("PAGES_TOUCHED", "%lu", touched);
    orc_kv("TOUCH_SUM", "%lu", sum);
    orc_check("MUNMAP", munmap(m, GIB) == 0);
    orc_check("LARGE_MAP_AVAILABLE", 1);
    return orc_end();
}
