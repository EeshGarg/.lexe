/* Compares argv[0] against /proc/self/exe. A launcher that rewrites argv[0], or
 * runs the program through a copy or a symlink, shows up here. */
#include "oracle.h"
#include <unistd.h>

int main(int argc, char **argv) {
    char exe[4096];
    ssize_t n;
    orc_begin("linux-interface-argv0");
    orc_obs("ARGV0", "%s", argc > 0 ? argv[0] : "(none)");
    n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n > 0) exe[n] = 0; else strcpy(exe, "(unavailable)");
    orc_obs("PROC_SELF_EXE", "%s", exe);
    orc_kv("ARGV0_IS_ABSOLUTE", "%s", (argc > 0 && argv[0][0] == 47) ? "yes" : "no");
    orc_kv("ARGV0_EQUALS_SELF_EXE", "%s", (argc > 0 && strcmp(argv[0], exe) == 0) ? "yes" : "no");
    orc_check("SELF_EXE_READABLE", n > 0);
    return orc_end();
}
