/* A type that exists in BOTH the shared library and the executable.
 *
 * That is the whole point: a C++ exception thrown inside a .so and caught in the
 * program that loaded it only works if the two agree on the type's identity --
 * one typeinfo, one vtable, one unwinder. They agree because the class has a
 * key function (the out-of-line destructor) and default visibility, so exactly
 * one copy of its typeinfo exists and the dynamic linker unifies it. Get that
 * wrong -- hidden visibility, or a header-only class in two translation units
 * that never get unified -- and the catch silently misses, std::terminate runs,
 * and the program aborts with no handler having been reached.
 */
#ifndef LEXE_LIBTHROWER_H
#define LEXE_LIBTHROWER_H

#include <stdexcept>
#include <string>
#include <typeinfo>

class ThrowerError : public std::runtime_error {
public:
    explicit ThrowerError(const std::string &what, int code);
    ~ThrowerError() override;          // key function: anchors the typeinfo
    int code() const { return code_; }

private:
    int code_;
};

/* Each of these throws from INSIDE the shared object. */
void thrower_throw_runtime(const char *what);
void thrower_throw_custom(const char *what, int code);
void thrower_throw_int(int value);

/* The library's own view of the type, for an identity comparison across the
 * boundary. Returned by reference: a type_info is not copyable. */
const std::type_info &thrower_typeid();

/* Something that destructs as the exception unwinds THROUGH the library. */
int thrower_unwind_count();
void thrower_throw_through_scope(const char *what);

#endif
