// fault — see fault.hpp.

#include "core/fault.hpp"

#include "core/util.hpp"

#include <optional>
#include <string>

namespace lexe::fault {

void maybe(const char* site) {
    const std::optional<std::string> active = util::get_env("LEXE_TEST_FAULT");
    if (active.has_value() && *active == site) {
        throw Injected(site);
    }
}

} // namespace lexe::fault
