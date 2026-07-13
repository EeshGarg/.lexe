// versioncmp — the "semver-lite" total order of FORMAT-0.1 §8. Split both
// versions on '.'; compare component-wise (numerically when both components
// are all ASCII digits, as byte strings otherwise); a version that is a
// strict prefix (fewer components) is smaller.

#include "core/versioncmp.hpp"

#include <algorithm>
#include <cstddef>

namespace lexe {

namespace {

int sign_of(int c) { return c < 0 ? -1 : (c > 0 ? 1 : 0); }

/// "All ASCII digits" per FORMAT-0.1 §8. The empty component is not treated
/// as numeric — it falls through to the byte-string compare, which keeps the
/// order total for degenerate inputs like "1." or "".
bool all_ascii_digits(std::string_view s) {
    if (s.empty()) return false;
    return std::all_of(s.begin(), s.end(),
                       [](char c) { return c >= '0' && c <= '9'; });
}

/// Numeric comparison of two digit strings of arbitrary length (no integer
/// conversion, so no overflow): strip leading zeros, then a longer string is
/// larger, then compare bytewise.
int compare_numeric(std::string_view a, std::string_view b) {
    a.remove_prefix(std::min(a.find_first_not_of('0'), a.size()));
    b.remove_prefix(std::min(b.find_first_not_of('0'), b.size()));
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    return sign_of(a.compare(b));
}

int compare_component(std::string_view a, std::string_view b) {
    if (all_ascii_digits(a) && all_ascii_digits(b)) {
        return compare_numeric(a, b);
    }
    // char_traits<char>::compare orders like unsigned bytes (memcmp).
    return sign_of(a.compare(b));
}

} // namespace

int compare_versions(std::string_view a, std::string_view b) {
    constexpr std::size_t npos = std::string_view::npos;
    std::size_t pa = 0;
    std::size_t pb = 0;
    bool more_a = true;
    bool more_b = true;
    while (more_a && more_b) {
        const std::size_t dot_a = a.find('.', pa);
        const std::size_t dot_b = b.find('.', pb);
        const std::string_view ca =
            a.substr(pa, dot_a == npos ? npos : dot_a - pa);
        const std::string_view cb =
            b.substr(pb, dot_b == npos ? npos : dot_b - pb);
        const int c = compare_component(ca, cb);
        if (c != 0) return c;
        more_a = dot_a != npos;
        more_b = dot_b != npos;
        pa = dot_a + 1; // wraps to 0 when dot_a == npos; unused then
        pb = dot_b + 1;
    }
    // All shared components equal: a strict prefix (fewer components) is
    // smaller (FORMAT-0.1 §8).
    if (more_a == more_b) return 0;
    return more_a ? 1 : -1;
}

bool version_less(std::string_view a, std::string_view b) {
    return compare_versions(a, b) < 0;
}

} // namespace lexe
