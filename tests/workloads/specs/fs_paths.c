/* Reports which of the usual environment-directed paths it was given and which
 * of them it can actually write to. A specimen whose whole job is to describe the
 * filesystem view it was handed. */
#include "oracle.h"
#include <unistd.h>

static void probe(const char *label, const char *dir) {
    char p[4096];
    int fd;
    if (!dir || !*dir) { orc_kv(label, "unset"); return; }
    orc_obs(label, "%s", dir);
    snprintf(p, sizeof p, "%s/lexe-wl-probe-%ld", dir, (long)getpid());
    fd = open(p, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        printf("%s_WRITABLE=no\n", label);
        printf("%s_ERRNO=%s\n", label, orc_errno_name(errno));
        return;
    }
    close(fd);
    unlink(p);
    printf("%s_WRITABLE=yes\n", label);
}

int main(void) {
    orc_begin("linux-fs-path-environment");
    probe("HOME", getenv("HOME"));
    probe("XDG_DATA_HOME", getenv("XDG_DATA_HOME"));
    probe("XDG_CONFIG_HOME", getenv("XDG_CONFIG_HOME"));
    probe("XDG_CACHE_HOME", getenv("XDG_CACHE_HOME"));
    probe("TMPDIR_OR_TMP", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
    probe("CWD_DOT", ".");
    orc_check("CWD_USABLE", access(".", W_OK) == 0);
    return orc_end();
}
