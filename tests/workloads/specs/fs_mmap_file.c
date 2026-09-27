/* mmap of a file, written through the mapping, msync-ed, then verified through
 * an ordinary read: the mapping and the file must agree. */
#include "oracle.h"
#include <sys/mman.h>
#include <unistd.h>

#define LEN 65536

int main(void) {
    int fd;
    unsigned char *m;
    unsigned char check[LEN];
    unsigned i;
    orc_begin("linux-fs-mmap-file");
    fd = open("mapped.dat", O_RDWR | O_CREAT | O_TRUNC, 0600);
    orc_check("OPEN", fd >= 0);
    orc_check("SIZED", ftruncate(fd, LEN) == 0);
    m = (unsigned char *)mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    orc_check("MMAP", m != MAP_FAILED);
    if (m == MAP_FAILED) { orc_kv("MMAP_ERRNO", "%s", orc_errno_name(errno)); return orc_end(); }
    for (i = 0; i < LEN; i++) m[i] = (unsigned char)((i * 13 + 5) & 0xff);
    orc_check("MSYNC", msync(m, LEN, MS_SYNC) == 0);
    orc_kv("MAP_HASH", "%016lx", orc_fnv1a(m, LEN));
    orc_check("MUNMAP", munmap(m, LEN) == 0);
    lseek(fd, 0, SEEK_SET);
    orc_check("READ_BACK", read(fd, check, LEN) == LEN);
    orc_kv("FILE_HASH", "%016lx", orc_fnv1a(check, LEN));
    close(fd);
    return orc_end();
}
