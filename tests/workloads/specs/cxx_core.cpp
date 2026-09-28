/* The C++ language surface, as a function of -std.
 *
 * The corpus had exactly two C++ specimens, both of the same program, which made
 * "C/C++" a dimension in name only. This one is built under four different
 * language standards and reports which it got, so the four specimens are a
 * genuine axis rather than four copies: __cplusplus is a deterministic value
 * that differs per specimen BY DESIGN, and everything else must be identical
 * under all four -- which is the actual claim being made, that none of these
 * behaviours depends on the standard the program was compiled against.
 *
 * What it exercises, all of it runtime rather than compile-time:
 *   - RTTI: typeid identity and dynamic_cast, up and across a hierarchy
 *   - exception unwinding, caught by base reference, with destructors running
 *   - static initialisation order within one translation unit
 *   - the containers and algorithms every real C++ program links
 *   - a lambda through std::function, which is an indirect call through the heap
 *
 * Nothing here prints a pointer, an address or a mangled name: typeid().name()
 * is ABI-dependent text, so what is asserted is the IDENTITY relation between
 * type_infos and never the spelling of one.
 */
#include "oracle.h"

#include <algorithm>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <vector>

namespace {

int destructor_calls = 0;
int init_order = 0;

struct Ordered {
    explicit Ordered(int tag) { init_order = init_order * 10 + tag; }
};
Ordered first(1);
Ordered second(2);

struct Base {
    virtual ~Base() { destructor_calls++; }
    virtual int value() const { return 1; }
};
struct Derived : Base {
    int value() const override { return 2; }
};
struct Unrelated : Base {
    int value() const override { return 3; }
};

struct Guarded {
    int *counter;
    explicit Guarded(int *c) : counter(c) {}
    ~Guarded() { (*counter)++; }
};

int unwound = 0;

void throws_through_a_scope() {
    Guarded g(&unwound);           // its destructor must run as the stack unwinds
    throw std::runtime_error("deliberate");
}

}  // namespace

int main() {
    orc_begin("linux-cxx-core");

    /* Which standard this specimen actually got. Deterministic, and different
     * per specimen on purpose. */
    orc_kv("CXX_STANDARD", "%ld", (long)__cplusplus);

    orc_kv("STATIC_INIT_ORDER", "%d", init_order);
    orc_check("STATIC_INIT_IN_DECLARATION_ORDER", init_order == 12);

    Derived d;
    Unrelated u;
    Base *as_base = &d;

    orc_check("TYPEID_MATCHES_DYNAMIC_TYPE", typeid(*as_base) == typeid(Derived));
    orc_check("TYPEID_DISTINGUISHES_SIBLINGS", typeid(d) != typeid(u));
    orc_check("DYNAMIC_CAST_DOWN_SUCCEEDS", dynamic_cast<Derived *>(as_base) != nullptr);
    orc_check("DYNAMIC_CAST_SIDEWAYS_FAILS", dynamic_cast<Unrelated *>(as_base) == nullptr);
    orc_kv("VIRTUAL_DISPATCH", "%d", as_base->value());
    orc_check("VIRTUAL_DISPATCH_IS_2", as_base->value() == 2);

    std::string what;
    bool caught_by_base_ref = false;
    try {
        throws_through_a_scope();
    } catch (const std::exception &e) {       // caught by BASE reference
        caught_by_base_ref = true;
        what = e.what();
    } catch (...) {
        what = "wrong-handler";
    }
    orc_check("EXCEPTION_CAUGHT_BY_BASE_REF", caught_by_base_ref);
    orc_kv("EXCEPTION_WHAT", "%s", what.c_str());
    orc_kv("UNWIND_DESTRUCTORS", "%d", unwound);
    orc_check("DESTRUCTOR_RAN_DURING_UNWIND", unwound == 1);

    std::vector<std::string> names{"gamma", "alpha", "beta"};
    std::sort(names.begin(), names.end());
    std::string joined;
    for (const std::string &n : names) {
        if (!joined.empty()) joined += ",";
        joined += n;
    }
    orc_kv("SORTED", "%s", joined.c_str());

    std::map<std::string, int> m;
    for (const std::string &n : names) m[n] = static_cast<int>(n.size());
    orc_kv("MAP_SIZE", "%d", static_cast<int>(m.size()));
    orc_kv("MAP_ALPHA", "%d", m["alpha"]);

    int captured = 19;
    std::function<int(int)> f = [captured](int x) { return x * captured; };
    orc_kv("LAMBDA_RESULT", "%d", f(7));
    orc_check("LAMBDA_THROUGH_STD_FUNCTION", f(7) == 133);

    {
        Base *heap = new Derived();
        delete heap;                          // virtual destructor
    }
    orc_kv("DESTRUCTOR_CALLS", "%d", destructor_calls);
    orc_check("VIRTUAL_DESTRUCTOR_RAN", destructor_calls >= 1);

    return orc_end();
}
