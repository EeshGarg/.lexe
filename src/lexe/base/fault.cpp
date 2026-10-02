// fault — see fault.hpp.

#include "lexe/base/fault.hpp"

#include "lexe/base/util.hpp"

#include <optional>
#include <string>

namespace lexe::fault {

void maybe(const char* site) {
    if (active(site)) throw Injected(site);
}

bool active(const char* site) {
    const std::optional<std::string> fault = util::get_env("LEXE_TEST_FAULT");
    return fault.has_value() && *fault == site;
}

} // namespace lexe::fault
