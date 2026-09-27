/* A C++ specimen, which is a different packaging problem from C: it pulls in
 * libstdc++ and libgcc_s (unless statically linked), runs static constructors
 * before main, unwinds through a thrown exception, and uses std::thread and the
 * iostream machinery. Built twice: once against the shared C++ runtime and once
 * with -static-libstdc++ -static-libgcc. */
#include <algorithm>
#include <exception>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

int construction_order = 0;

struct Early {
    Early() { construction_order = construction_order * 10 + 1; }
};
struct Late {
    Late() { construction_order = construction_order * 10 + 2; }
};

Early early;
Late late;

struct WorkloadError : std::runtime_error {
    explicit WorkloadError(const std::string &what) : std::runtime_error(what) {}
};

}  // namespace

int main() {
    std::cout.setf(std::ios::unitbuf);
    std::cout << "FIXTURE_ID=linux-cxx-runtime\n";
    std::cout << "STATIC_INIT_ORDER=" << construction_order << "\n";

    int caught = 0;
    std::string message;
    try {
        throw WorkloadError("deliberate");
    } catch (const std::runtime_error &e) {
        caught = 1;
        message = e.what();
    } catch (...) {
        caught = 2;
    }
    std::cout << "EXCEPTION_CAUGHT=" << (caught == 1 ? "by-base-ref" : "wrong") << "\n";
    std::cout << "EXCEPTION_WHAT=" << message << "\n";

    long total = 0;
    std::mutex m;
    std::vector<std::thread> pool;
    for (int t = 0; t < 4; ++t) {
        pool.emplace_back([t, &total, &m]() {
            long acc = 0;
            for (int i = 0; i < 10000; ++i) acc += (t * 31 + i) % 97;
            std::lock_guard<std::mutex> g(m);
            total += acc;
        });
    }
    for (auto &th : pool) th.join();
    std::cout << "THREADS_JOINED=" << pool.size() << "\n";
    std::cout << "THREAD_TOTAL=" << total << "\n";

    std::vector<std::string> v{"gamma", "alpha", "beta"};
    std::sort(v.begin(), v.end());
    std::cout << "SORTED=" << v[0] << "," << v[1] << "," << v[2] << "\n";

    bool ok = (construction_order == 12) && (caught == 1) && (v[0] == "alpha");
    std::cout << "RESULT=" << (ok ? "PASS" : "FAIL") << "\n";
    return ok ? 0 : 1;
}
