/* exec through a PATH lookup, rather than by absolute path.
 *
 *   argv[1]  the bare program NAME to find on PATH (no slash)
 *
 * Every other exec specimen in the corpus names its target by absolute path, so
 * the corpus never once depended on PATH being right. Real software does,
 * constantly -- a launcher script, a helper invoked by name, a plugin that shells
 * out -- and PATH is exactly the kind of thing a sandbox, a service manager or a
 * relauncher rewrites without meaning to change behaviour.
 *
 * The specimen reports the PATH it was given as an OBSERVATION (it is an
 * environment value and would otherwise be a deterministic key that changes with
 * the corpus root), and asserts only the things that are genuinely invariant:
 * that the name contains no slash, that execvp found it, and that the program
 * which took over is the intended one -- proved by the target's own output and
 * exit code, not by the name that was looked up.
 */
#include "oracle.h"

#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *name = argc > 1 ? argv[1] : "";
    const char *path = getenv("PATH");
    char *args[4];

    orc_begin("linux-exec-path");
    orc_kv("TARGET_NAME", "%s", name);
    orc_check("TARGET_NAME_HAS_NO_SLASH",
              name[0] != '\0' && strchr(name, '/') == NULL);
    orc_obs("PATH", "%s", path ? path : "(unset)");
    orc_kv("PATH_PRESENT", "%s", path && *path ? "yes" : "no");
    orc_kv("PHASE", "pre-exec");
    orc_kv("LOOKUP", "execvp");
    fflush(stdout);

    args[0] = (char *)name;            /* argv[0] is the bare name, as a shell does */
    args[1] = (char *)"exec-path";
    args[2] = (char *)"29";            /* the target's exit code, so the status
                                        * proves WHICH program took over */
    args[3] = NULL;
    execvp(name, args);

    /* Only reached if the lookup failed, which is a legitimate outcome to be
     * able to report rather than a crash. */
    orc_kv("EXECVP_ERRNO", "%s", orc_errno_name(errno));
    orc_check("EXECVP_FOUND_IT", 0);
    return orc_end();
}
