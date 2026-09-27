/* Redirects its own stdout to a file with dup2, writes there, restores the
 * original, and verifies the file content: a program that rearranges its own
 * descriptor table mid-run.
 *
 * Note for anyone editing this: while fd 1 points at the file, ANY oracle output
 * lands in the file too. So every outcome is held in a variable and reported
 * only after the original stdout is back. The first version of this specimen got
 * that wrong, and its own direct-execution baseline caught it. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    int saved, fd, dup2_ok, restore_ok;
    char buf[128];
    ssize_t n;
    orc_begin("linux-io-dup2-redirect");
    fflush(stdout);
    saved = dup(1);
    fd = open("redirected.txt", O_RDWR | O_CREAT | O_TRUNC, 0600);
    dup2_ok = (fd >= 0 && dup2(fd, 1) == 1);
    if (dup2_ok) {
        printf("REDIRECTED_LINE=yes\n");
        fflush(stdout);
    }
    restore_ok = (saved >= 0 && dup2(saved, 1) == 1);
    if (saved >= 0) close(saved);
    /* stdout is the real stdout again from here on. */
    orc_check("DUP_SAVED", saved >= 0);
    orc_check("OPEN_TARGET", fd >= 0);
    orc_check("DUP2_OK", dup2_ok);
    orc_check("RESTORE_OK", restore_ok);
    if (fd >= 0) lseek(fd, 0, SEEK_SET);
    n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : -1;
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    if (fd >= 0) close(fd);
    orc_kv("FILE_BYTES", "%ld", (long)n);
    orc_check("FILE_CONTENT_OK", strcmp(buf, "REDIRECTED_LINE=yes\n") == 0);
    orc_kv("STDOUT_RESTORED", "yes");
    return orc_end();
}
