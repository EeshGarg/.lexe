/* An exception thrown inside a shared library and caught in the executable.
 *
 *   argv[1]  caught | uncaught
 *
 * This is the C++ ABI's most load-bearing cross-module guarantee and the one
 * most likely to be quietly broken by how a program was linked or packaged: the
 * throw site is in libthrower.so, the handler is in the executable, and for the
 * catch to fire at all the two must share one typeinfo, one vtable and one
 * unwinder. If a packaging step gives the library its own copy of the C++
 * runtime, or strips the symbol that unifies the typeinfo, the handler is
 * skipped, std::terminate runs, and the program aborts having "handled" nothing.
 *
 * Four independent things are asserted, none of which is the spelling of a
 * mangled name:
 *   - the identity relation typeid(ThrowerError) == thrower_typeid(), compared
 *     ACROSS the boundary rather than by name;
 *   - a catch by base reference for a type derived inside the library;
 *   - that destructors inside the library ran while unwinding out of it;
 *   - that a non-class exception (a bare int) crosses too.
 *
 * `uncaught` is the same binary with the handler removed from the path: the
 * exception escapes main and std::terminate aborts. Declared as a death, so an
 * accidental abort and an intentional one remain distinguishable.
 */
#include "oracle.h"
#include "libthrower.h"

#include <cstring>
#include <string>

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "caught";
    orc_begin("linux-cxx-so-throw");
    orc_kv("MODE", "%s", mode);

    if (std::strcmp(mode, "uncaught") == 0) {
        orc_kv("EXCEPTION_SOURCE", "shared-library");
        orc_expect_death("sigabrt-std-terminate");
        fflush(stdout);
        thrower_throw_custom("escapes main", 5);
        orc_kv("UNREACHED", "yes");
        return 90;
    }

    /* One typeinfo, seen from both sides. Compared by identity, never by name:
     * typeid().name() is ABI text and asserting it would be asserting the
     * compiler's mangling scheme instead of the property under test. */
    orc_check("TYPEINFO_UNIFIED_ACROSS_SO",
              typeid(ThrowerError) == thrower_typeid());

    bool caught_runtime = false;
    std::string what;
    try {
        thrower_throw_runtime("from-the-library");
    } catch (const std::runtime_error &e) {
        caught_runtime = true;
        what = e.what();
    } catch (...) {
        what = "wrong-handler";
    }
    orc_check("CAUGHT_STD_RUNTIME_ERROR_FROM_SO", caught_runtime);
    orc_kv("RUNTIME_WHAT", "%s", what.c_str());

    bool caught_custom = false, by_base_ref = false;
    int code = -1;
    try {
        thrower_throw_custom("custom-from-the-library", 42);
    } catch (const std::exception &e) {      /* BASE reference, derived type */
        by_base_ref = true;
        const ThrowerError *t = dynamic_cast<const ThrowerError *>(&e);
        if (t) { caught_custom = true; code = t->code(); }
        what = e.what();
    } catch (...) {
        what = "wrong-handler";
    }
    orc_check("CAUGHT_BY_BASE_REFERENCE", by_base_ref);
    orc_check("DYNAMIC_CAST_ACROSS_SO", caught_custom);
    orc_kv("CUSTOM_CODE", "%d", code);
    orc_kv("CUSTOM_WHAT", "%s", what.c_str());

    int before = thrower_unwind_count();
    bool caught_scope = false;
    try {
        thrower_throw_through_scope("unwinds-out-of-the-library");
    } catch (const ThrowerError &e) {
        caught_scope = true;
        code = e.code();
    }
    orc_check("CAUGHT_EXACT_DERIVED_TYPE", caught_scope);
    orc_kv("SCOPE_CODE", "%d", code);
    orc_kv("LIBRARY_DESTRUCTORS_RUN", "%d", thrower_unwind_count() - before);
    orc_check("UNWOUND_THROUGH_THE_LIBRARY",
              thrower_unwind_count() - before == 1);

    bool caught_int = false;
    int got = 0;
    try {
        thrower_throw_int(1234);
    } catch (int v) {                         /* a non-class exception crosses too */
        caught_int = true;
        got = v;
    } catch (...) {
    }
    orc_check("CAUGHT_NON_CLASS_EXCEPTION", caught_int);
    orc_kv("INT_EXCEPTION_VALUE", "%d", got);

    return orc_end();
}
