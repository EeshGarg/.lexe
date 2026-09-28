// A C++ product whose dependency is a C static library the same build produced.
// Three tools in one recipe -- cc, ar, c++ -- and the archive has to be built
// before the link, which is an ordering a build system has to get right on a
// machine the publisher never saw.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "clib.h"

int main(int argc, char **argv) {
    const char *id = std::getenv("FIXTURE_ID");
    std::printf("FIXTURE_ID=%s\n", id ? id : "portable-cxx-c-archive");
    std::printf("PAYLOAD_KIND=portable-source\n");
    std::printf("MAIN_LANGUAGE=c++\n");
    std::printf("DEPENDENCY_KIND=c-static-archive\n");
    std::printf("CLIB_ANSWER=%d\n", clib_answer());
    std::printf("CLIB_ID=%s\n", clib_id());
    std::vector<int> v(4, clib_answer());
    long total = 0;
    for (std::size_t i = 0; i < v.size(); ++i) total += v[i];
    std::printf("VECTOR_TOTAL=%ld\n", total);
    std::printf("ARGC=%d\n", argc);
    std::printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    bool ok = clib_answer() == 2718 && std::strcmp(clib_id(), "clib-archive-1") == 0
              && total == 10872 && argc >= 1 && argv[0];
    std::printf("ARCHIVE_LINKED=%s\n", ok ? "yes" : "no");
    std::printf("RESULT=%s\n", ok ? "PASS" : "FAIL");
    return 0;
}
