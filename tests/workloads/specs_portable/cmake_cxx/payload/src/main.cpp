// cmake driving the C++ compiler. The standard is set by a cmake property
// (CXX_STANDARD) rather than by a -std flag in the recipe, so what this reports
// measures whether that property reached the compiler.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <numeric>

int main(int argc, char **argv) {
    const char *id = std::getenv("FIXTURE_ID");
    std::printf("FIXTURE_ID=%s\n", id ? id : "portable-cmake-cxx");
    std::printf("PAYLOAD_KIND=portable-source\n");
    std::printf("BUILD_SYSTEM=cmake\n");
    std::printf("LANGUAGE=c++\n");
    std::printf("CPLUSPLUS=%ld\n", static_cast<long>(__cplusplus));
    std::vector<int> v(64);
    std::iota(v.begin(), v.end(), 1);
    int sum = std::accumulate(v.begin(), v.end(), 0);
    std::printf("VECTOR_SUM=%d\n", sum);
    std::string s = "cmake-cxx";
    std::printf("STRING_VALUE=%s\n", s.c_str());
    std::printf("ARGC=%d\n", argc);
    std::printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    bool ok = sum == 2080 && s == "cmake-cxx" && argc >= 1 && argv[0];
    std::printf("RESULT=%s\n", ok ? "PASS" : "FAIL");
    return 0;
}
