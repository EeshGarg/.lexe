#pragma once
// versioncmp — the "semver-lite" total order of FORMAT-0.1 §8. Split on '.',
// compare component-wise (numeric when both components are all ASCII digits,
// otherwise byte-string), strict prefix is smaller. This is the ONLY version
// ordering the 0.1 runtime uses (updater rule §7.7: strictly greater).

#include <string_view>

namespace lexe {

/// Three-way compare: negative when a < b, 0 when equal, positive when a > b
/// (FORMAT-0.1 §8).
int compare_versions(std::string_view a, std::string_view b);

/// Convenience: a < b under FORMAT-0.1 §8.
bool version_less(std::string_view a, std::string_view b);

} // namespace lexe
