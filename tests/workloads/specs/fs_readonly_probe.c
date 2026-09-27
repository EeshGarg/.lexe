/* Attempts to write into three locations a confined program has no business
 * writing to, and reports the errno for each. Every outcome is a legitimate
 * observation: it is describing the filesystem policy it is under, not asserting
 * one. The only self-check is that it survived all three attempts. */
#include "oracle.h"
#include <unistd.h>

static void attempt(const char *label, const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        printf("%s=writable\n", label);
        close(fd);
        unlink(path);
        return;
    }
    printf("%s=denied\n", label);
    printf("%s_ERRNO=%s\n", label, orc_errno_name(errno));
}

int main(void) {
    orc_begin("linux-fs-readonly-probe");
    attempt("USR_WRITE", "/usr/lexe-wl-probe");
    attempt("ETC_WRITE", "/etc/lexe-wl-probe");
    attempt("ROOT_WRITE", "/lexe-wl-probe");
    orc_kv("ETC_PASSWD_READABLE", "%s", access("/etc/passwd", R_OK) == 0 ? "yes" : "no");
    orc_check("SURVIVED_ALL_PROBES", 1);
    return orc_end();
}
