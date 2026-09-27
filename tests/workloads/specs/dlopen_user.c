/* dlopen of a library built alongside it. argv[1] is the library path; when the
 * path does not exist the specimen reports the failure as its result rather
 * than crashing -- that is the point of the missing-library variant. */
#include "oracle.h"
#include <dlfcn.h>
#include <unistd.h>

int main(int argc, char **argv) {
    void *h;
    int (*probe)(int);
    const char *(*name)(void);
    int expect_ok;
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-dlopen");
    if (argc < 3) { orc_kv("USAGE", "dlopen_user <path> <expect:ok|fail>"); return 2; }
    expect_ok = (strcmp(argv[2], "ok") == 0);
    h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    orc_kv("DLOPEN", "%s", h ? "ok" : "fail");
    if (!h) {
        orc_obs("DLERROR", "%s", dlerror());
        orc_check("OUTCOME_AS_DECLARED", !expect_ok);
        return orc_end();
    }
    orc_check("OUTCOME_AS_DECLARED", expect_ok);
    probe = (int (*)(int))dlsym(h, "plugin_probe");
    name = (const char *(*)(void))dlsym(h, "plugin_name");
    orc_check("DLSYM_PROBE", probe != NULL);
    orc_check("DLSYM_NAME", name != NULL);
    if (probe) orc_kv("PROBE_14", "%d", probe(14));
    if (name) orc_kv("PLUGIN_NAME", "%s", name());
    orc_kv("DLCLOSE", "%d", dlclose(h));
    return orc_end();
}
