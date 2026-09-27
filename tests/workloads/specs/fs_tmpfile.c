/* Temporary files the correct way: mkstemp under TMPDIR, write, read back,
 * unlink. Leaves nothing behind, and says where TMPDIR pointed. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    char tmpl[512];
    const char *tmp = getenv("TMPDIR");
    int fd;
    char buf[64];
    ssize_t n;
    orc_begin("linux-fs-tmpfile-mkstemp");
    if (!tmp || !*tmp) tmp = "/tmp";
    orc_obs("TMPDIR", "%s", tmp);
    snprintf(tmpl, sizeof tmpl, "%s/lexe-wl-XXXXXX", tmp);
    fd = mkstemp(tmpl);
    orc_check("MKSTEMP", fd >= 0);
    if (fd < 0) { orc_kv("MKSTEMP_ERRNO", "%s", orc_errno_name(errno)); return orc_end(); }
    orc_obs("TMPFILE", "%s", tmpl);
    orc_check("WROTE", write(fd, "TEMP-PAYLOAD", 12) == 12);
    lseek(fd, 0, SEEK_SET);
    n = read(fd, buf, sizeof buf - 1);
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    orc_check("READ_BACK_OK", strcmp(buf, "TEMP-PAYLOAD") == 0);
    close(fd);
    orc_check("UNLINKED", unlink(tmpl) == 0);
    orc_check("GONE", access(tmpl, F_OK) != 0);
    orc_kv("LEAVES_NO_TRACE", "yes");
    return orc_end();
}
