/* Builds a 3-level directory tree of 40 files, walks it with opendir/readdir,
 * and reports counts and a name-order-independent checksum. */
#include "oracle.h"
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned long files = 0, dirs = 0, namesum = 0;

static void walk(const char *path, int depth) {
    DIR *d = opendir(path);
    struct dirent *e;
    if (!d || depth > 8) { if (d) closedir(d); return; }
    while ((e = readdir(d)) != NULL) {
        char sub[1024];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        snprintf(sub, sizeof sub, "%s/%s", path, e->d_name);
        if (lstat(sub, &st) != 0) continue;
        namesum += orc_fnv1a((const unsigned char *)e->d_name, strlen(e->d_name)) & 0xffff;
        if (S_ISDIR(st.st_mode)) { dirs++; walk(sub, depth + 1); }
        else files++;
    }
    closedir(d);
}

int main(void) {
    int a, b, c;
    orc_begin("linux-fs-directory-tree");
    mkdir("tree", 0700);
    for (a = 0; a < 2; a++) {
        char p1[64];
        snprintf(p1, sizeof p1, "tree/a%d", a);
        mkdir(p1, 0700);
        for (b = 0; b < 2; b++) {
            char p2[128];
            snprintf(p2, sizeof p2, "%s/b%d", p1, b);
            mkdir(p2, 0700);
            for (c = 0; c < 10; c++) {
                char p3[256];
                FILE *f;
                snprintf(p3, sizeof p3, "%s/f%02d.dat", p2, c);
                f = fopen(p3, "w");
                if (f) { fprintf(f, "%d-%d-%d\n", a, b, c); fclose(f); }
            }
        }
    }
    walk("tree", 0);
    orc_kv("DIRS_FOUND", "%lu", dirs);
    orc_kv("FILES_FOUND", "%lu", files);
    orc_kv("NAMESUM", "%lu", namesum);
    orc_check("TREE_SHAPE", dirs == 6 && files == 40);
    return orc_end();
}
