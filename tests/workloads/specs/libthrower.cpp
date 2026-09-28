/* The throwing half. Built as libthrower.so; see libthrower.h for why the type's
 * identity has to survive the .so boundary. */
#include "libthrower.h"

ThrowerError::ThrowerError(const std::string &what, int code)
    : std::runtime_error(what), code_(code) {}

ThrowerError::~ThrowerError() = default;

namespace {
int unwind_count = 0;

struct Guarded {
    ~Guarded() { unwind_count++; }
};
}  // namespace

void thrower_throw_runtime(const char *what) { throw std::runtime_error(what); }

void thrower_throw_custom(const char *what, int code) {
    throw ThrowerError(what, code);
}

void thrower_throw_int(int value) { throw value; }

const std::type_info &thrower_typeid() { return typeid(ThrowerError); }

int thrower_unwind_count() { return unwind_count; }

void thrower_throw_through_scope(const char *what) {
    Guarded g;                      /* must be destroyed as the stack unwinds
                                     * out of the library and into the caller */
    throw ThrowerError(what, 77);
}
