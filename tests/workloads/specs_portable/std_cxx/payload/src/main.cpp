// One source, four C++ standards.
//
// Written to C++11 so it compiles unchanged under -std=c++11, c++14, c++17 and
// c++20. Nothing here uses a feature that a later standard removed
// (std::random_shuffle, std::auto_ptr) or that an earlier one lacks, because the
// specimen is about what __cplusplus says the compiler was given, and a source
// that only builds under one of the four could not measure that.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

static const char *isa() {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#else
    return "unknown";
#endif
}

int main(int argc, char **argv) {
    const char *id = std::getenv("FIXTURE_ID");
    std::printf("FIXTURE_ID=%s\n", id ? id : "portable-std-cxx");
    std::printf("PAYLOAD_KIND=portable-source\n");
    std::printf("LANGUAGE=c++\n");
    std::printf("CPLUSPLUS=%ld\n", static_cast<long>(__cplusplus));

    // 1 + 2 + ... + 64 == 2080, computed by hand, not by a second copy of the
    // same loop.
    std::vector<int> v;
    for (int i = 1; i <= 64; ++i) v.push_back(i);
    int sum = 0;
    std::for_each(v.begin(), v.end(), [&sum](int x) { sum += x; });
    std::printf("VECTOR_SUM=%d\n", sum);

    std::string s = "portable";
    s += "-source";
    std::printf("STRING_CONCAT=%s\n", s.c_str());

    bool caught = false;
    try {
        throw std::string("deliberate");
    } catch (const std::string &e) {
        caught = (e == "deliberate");
    }
    std::printf("EXCEPTION_CAUGHT=%s\n", caught ? "yes" : "no");
    std::printf("BUILD_ISA=%s\n", isa());
    std::printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    bool ok = (sum == 2080) && caught && s == "portable-source"
              && std::strcmp(isa(), "unknown") != 0 && argc >= 1 && argv[0];
    std::printf("RESULT=%s\n", ok ? "PASS" : "FAIL");
    return 0;
}
