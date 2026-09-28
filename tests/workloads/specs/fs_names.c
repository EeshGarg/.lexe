/* A filename is a byte string, not text.
 *
 *   argv[1]  the name to create, relative to the working directory
 *
 * The corpus already declares arguments containing spaces, Unicode and quotes.
 * A FILENAME is a different surface: it travels through the directory entry, the
 * readdir enumeration and every shell, path-joining routine and quoting layer in
 * between, and each of those is somewhere a legitimate name gets mangled or
 * lost. A name beginning with `-` becomes an option; a name containing a space
 * becomes two names; a Unicode name survives or does not depending on whether
 * something decoded and re-encoded it; a name with a quote or a `$` in it breaks
 * anything that builds a shell command by concatenation.
 *
 * Every one of these is a name a real user has on a real disk, so nothing here
 * is a hostile input: it is ordinary data that careless handling destroys.
 *
 * The name is declared by LENGTH IN BYTES and by HEX, never by appearance, so a
 * mangling is unambiguous rather than something that has to be eyeballed. The
 * file is located in the directory by an exact byte comparison of the entry
 * name, and the content by a delimiter, never by position.
 */
#include "oracle.h"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONTENT "<<<LEXE-FS-NAME-PAYLOAD>>>"

static void hexkv(const char *key, const char *s, size_t n) {
    /* 64 bytes of name is plenty to identify any mangling; beyond that the hex
     * is elided rather than printed, exactly as the argument specimens do. */
    char buf[160];
    size_t i;
    if (n > 64) {
        orc_kv(key, "(elided,%lu bytes)", (unsigned long)n);
        return;
    }
    for (i = 0; i < n; i++)
        snprintf(buf + i * 2, sizeof buf - i * 2, "%02x", (unsigned char)s[i]);
    buf[n * 2] = '\0';
    orc_kv(key, "%s", buf);
}

int main(int argc, char **argv) {
    const char *name = argc > 1 ? argv[1] : "";
    size_t len = strlen(name);
    FILE *f;
    char back[256];
    struct stat st;
    DIR *d;
    struct dirent *e;
    int found = 0, content_ok = 0;

    orc_begin("linux-fs-names");
    orc_kv("NAME_LEN", "%lu", (unsigned long)len);
    hexkv("NAME_HEX", name, len);
    if (!orc_check("NAME_NON_EMPTY", len > 0))
        return orc_end();

    /* fopen, not a shell: the name is passed to the kernel as bytes and nothing
     * in between gets a chance to reinterpret it. */
    f = fopen(name, "wb");
    if (!orc_check("CREATED", f != NULL)) {
        orc_kv("CREATE_ERRNO", "%s", orc_errno_name(errno));
        return orc_end();
    }
    fputs(CONTENT "\n", f);
    fclose(f);

    orc_check("LSTAT_OK", lstat(name, &st) == 0);
    orc_check("IS_REGULAR", S_ISREG(st.st_mode));

    f = fopen(name, "rb");
    if (orc_check("REOPENED", f != NULL)) {
        size_t n = fread(back, 1, sizeof back - 1, f);
        back[n] = '\0';
        fclose(f);
        content_ok = strncmp(back, CONTENT, sizeof(CONTENT) - 1) == 0;
    }
    orc_check("CONTENT_ROUNDTRIP", content_ok);
    orc_kv("CONTENT_DELIMITER", "%s", CONTENT);

    /* Enumeration is the half that a path-joining bug breaks: the file can exist
     * and still be invisible to whatever lists the directory. */
    d = opendir(".");
    if (orc_check("OPENDIR", d != NULL)) {
        while ((e = readdir(d)) != NULL) {
            if (strlen(e->d_name) == len && memcmp(e->d_name, name, len) == 0) {
                found = 1;
                break;
            }
        }
        closedir(d);
    }
    orc_check("FOUND_BY_EXACT_BYTES_IN_READDIR", found);

    orc_check("UNLINKED", unlink(name) == 0);
    orc_check("GONE", lstat(name, &st) != 0);
    return orc_end();
}
