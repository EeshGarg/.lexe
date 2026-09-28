// Compiled by the C++ compiler, linked by the C++ driver, and calls into a
// translation unit the C compiler produced. Two compilers, one product -- and
// the link has to be driven by c++ rather than cc, because only c++ knows to
// bring in the C++ runtime.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include "cpart.h"

int main(int argc, char **argv) {
    const char *id = std::getenv("FIXTURE_ID");
    std::printf("FIXTURE_ID=%s\n", id ? id : "portable-mixed-c-cxx");
    std::printf("PAYLOAD_KIND=portable-source\n");
    std::printf("TRANSLATION_UNITS=2\n");
    std::printf("MAIN_LANGUAGE=c++\n");
    std::printf("CPART_LANGUAGE=%s\n", cpart_language());
    std::printf("CPART_VALUE=%d\n", cpart_value());
    std::printf("CPART_MIX=%lu\n", cpart_mix(2166136261UL, 256));
    std::string s = std::string("mixed-") + "ok";
    std::printf("CXX_STRING=%s\n", s.c_str());
    std::printf("ARGC=%d\n", argc);
    std::printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    bool ok = cpart_value() == 1701 && std::strcmp(cpart_language(), "c") == 0
              && s == "mixed-ok" && argc >= 1 && argv[0];
    std::printf("BOTH_UNITS_LINKED=%s\n", ok ? "yes" : "no");
    std::printf("RESULT=%s\n", ok ? "PASS" : "FAIL");
    return 0;
}
