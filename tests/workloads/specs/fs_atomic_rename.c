/* The durable-write pattern: write a temp file, fsync it, fsync the directory,
 * rename over the target. Verifies the target content and that the temp is gone. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    int fd, dirfd;
    const char *payload = "atomic-payload-v1\n";
    orc_begin("linux-fs-atomic-rename");
    fd = open("data.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
    orc_check("OPEN_TMP", fd >= 0);
    orc_check("WRITE_TMP", write(fd, payload, strlen(payload)) == (ssize_t)strlen(payload));
    orc_check("FSYNC_FILE", fsync(fd) == 0);
    close(fd);
    dirfd = open(".", O_RDONLY | O_DIRECTORY);
    orc_check("OPEN_DIR", dirfd >= 0);
    orc_check("RENAME", rename("data.tmp", "data.final") == 0);
    orc_check("FSYNC_DIR", fsync(dirfd) == 0);
    close(dirfd);
    orc_check("TMP_GONE", access("data.tmp", F_OK) != 0);
    {
        char buf[64];
        FILE *f = fopen("data.final", "r");
        orc_check("FINAL_OPEN", f != NULL);
        if (f) {
            if (!fgets(buf, sizeof buf, f)) buf[0] = 0;
            fclose(f);
            orc_check("FINAL_CONTENT", strcmp(buf, payload) == 0);
        }
    }
    return orc_end();
}
