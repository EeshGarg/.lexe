/* Symlinks: creates one, reads it back, follows it, and checks that lstat and
 * stat disagree the way they should. */
#include "oracle.h"
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    struct stat st_l, st_f;
    char buf[256];
    ssize_t n;
    FILE *f;
    orc_begin("linux-fs-symlink");
    unlink("target.txt"); unlink("link.txt");
    f = fopen("target.txt", "w");
    orc_check("TARGET_CREATED", f != NULL);
    if (f) { fputs("symlink-target-v1\n", f); fclose(f); }
    orc_check("SYMLINK_CREATED", symlink("target.txt", "link.txt") == 0);
    n = readlink("link.txt", buf, sizeof buf - 1);
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    orc_kv("READLINK", "%s", buf);
    orc_check("LSTAT", lstat("link.txt", &st_l) == 0);
    orc_check("STAT", stat("link.txt", &st_f) == 0);
    orc_check("LSTAT_IS_LINK", S_ISLNK(st_l.st_mode) != 0);
    orc_check("STAT_IS_REGULAR", S_ISREG(st_f.st_mode) != 0);
    {
        char line[64];
        FILE *g = fopen("link.txt", "r");
        orc_check("FOLLOWED_OPEN", g != NULL);
        if (g) {
            if (!fgets(line, sizeof line, g)) line[0] = 0;
            fclose(g);
            orc_check("FOLLOWED_CONTENT", strcmp(line, "symlink-target-v1\n") == 0);
        }
    }
    return orc_end();
}
