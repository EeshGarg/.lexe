/* C++ at install time. A portable package whose recipe needs a C++ compiler is
 * a different toolchain claim from one that needs a C compiler, and a host that
 * has cc but not c++ is entirely ordinary -- so this recipe declares both and
 * the corpus records which the host actually had.
 *
 * What is exercised beyond "it compiles": static initialisation order across
 * two objects, an exception unwound through a function boundary, std::thread
 * (which drags in libpthread and the C++ runtime), and <algorithm>. Those are
 * the parts of a C++ build that break when a toolchain is incomplete rather
 * than absent -- a libstdc++ headers package missing, say.
 */
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <numeric>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

int init_order = 0;

struct First {
    First() { init_order = init_order * 10 + 1; }
};
struct Second {
    Second() { init_order = init_order * 10 + 2; }
};

First  g_first;
Second g_second;

int failures = 0;

void kv(const char* key, const std::string& value) {
    std::printf("%s=%s\n", key, value.c_str());
}
void kvn(const char* key, long long value) {
    std::printf("%s=%lld\n", key, value);
}
void check(const char* key, bool ok) {
    std::printf("%s=%s\n", key, ok ? "yes" : "no");
    if (!ok) ++failures;
}

void thrower() { throw std::runtime_error("deliberate"); }

const char* isa() {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#else
    return "unknown";
#endif
}

}  // namespace

int main(int argc, char** argv) {
    const char* id = std::getenv("FIXTURE_ID");
    kv("FIXTURE_ID", id ? id : "portable-cxx");
    kv("PAYLOAD_KIND", "portable-source");
    kv("LANGUAGE", "c++");
    kvn("CXX_STANDARD", __cplusplus);
    kvn("STATIC_INIT_ORDER", init_order);
    kv("BUILD_ISA", isa());

    std::string caught = "none";
    try {
        thrower();
    } catch (const std::exception& e) {
        caught = e.what();
    }
    kv("EXCEPTION_WHAT", caught);

    std::vector<int> v(64);
    std::iota(v.begin(), v.end(), 1);
    std::reverse(v.begin(), v.end());
    std::sort(v.begin(), v.end());
    kvn("VECTOR_SUM", std::accumulate(v.begin(), v.end(), 0LL));

    long long total = 0;
    std::vector<std::thread> threads;
    std::vector<long long> parts(4, 0);
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([i, &parts] {
            long long acc = 0;
            for (int k = 0; k < 100000; ++k) acc += (i + 1) * (k % 7);
            parts[static_cast<std::size_t>(i)] = acc;
        });
    }
    for (auto& t : threads) t.join();
    for (long long p : parts) total += p;
    kvn("THREADS_JOINED", static_cast<long long>(threads.size()));
    kvn("THREAD_TOTAL", total);

    std::printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    check("STATIC_INIT_BOTH_RAN", init_order == 12);
    check("EXCEPTION_CAUGHT", caught == "deliberate");
    check("SORT_RESTORED_ORDER", v.front() == 1 && v.back() == 64);
    check("ISA_KNOWN", std::strcmp(isa(), "unknown") != 0);
    check("ARGV0_PRESENT", argc >= 1 && argv[0] != nullptr && argv[0][0] != '\0');
    std::printf("RESULT=%s\n", failures == 0 ? "PASS" : "FAIL");
    return 0;
}
