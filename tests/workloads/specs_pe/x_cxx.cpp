/* A C++ PE. Different packaging problem from C: unless statically linked it needs
 * libstdc++-6.dll and libgcc_s_seh-1.dll beside the executable, which is the
 * bundled-runtime-DLL case done for real rather than simulated.
 *
 * It exercises static construction before main, an exception unwound through a
 * catch by base reference, iostreams, and the standard algorithms. It does NOT
 * use std::thread: this MinGW-w64 is the win32-threads build, where libstdc++
 * has no std::thread at all -- Win32 threading is covered by w_threads.c.
 *
 * Its own output goes through the same oracle file as every other specimen, so
 * the C++ runtime cannot change how it is observed. */
#include "oracle_win.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int construction_order = 0;

struct Early { Early() { construction_order = construction_order * 10 + 1; } };
struct Late  { Late()  { construction_order = construction_order * 10 + 2; } };

Early early;
Late late;

struct WorkloadError : std::runtime_error {
    explicit WorkloadError(const std::string &what) : std::runtime_error(what) {}
};

}  // namespace

int main() {
    orc_begin("pe-cxx-runtime");
    orc_kv("STATIC_INIT_ORDER", "%d", construction_order);

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
    orc_kv("EXCEPTION_CAUGHT", "%s", caught == 1 ? "by-base-ref" : "wrong");
    orc_kv("EXCEPTION_WHAT", "%s", message.c_str());

    std::vector<std::string> v{"gamma", "alpha", "beta"};
    std::sort(v.begin(), v.end());
    orc_kv("SORTED", "%s,%s,%s", v[0].c_str(), v[1].c_str(), v[2].c_str());

    long total = 0;
    for (int i = 0; i < 100000; ++i) total += (i * 31) % 97;
    orc_kv("ALGORITHM_TOTAL", "%ld", total);

    std::cout << "IOSTREAM_USED=yes" << std::endl;

    orc_check("STATIC_INIT_BEFORE_MAIN", construction_order == 12);
    orc_check("EXCEPTION_UNWOUND", caught == 1);
    orc_check("STDLIB_SORT_WORKED", v[0] == "alpha");
    return orc_end();
}
