#pragma once
// http — URL fetching (ARCHITECTURE.md #Modules; used by updater, FORMAT-0.1
// §7). `https://`/`http://` are fetched via a `curl` subprocess with an argv
// array (no shell — security invariant #3). `file://` URLs (percent-decoded)
// and plain filesystem paths are served via std::filesystem, which is what
// the test-suite uses (no network in tests).

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace lexe::http {

/// Download `url` to `dest` (parent directories are created; an existing file
/// is overwritten). curl invocation:
///   curl --fail -sS -L --max-time 120 --output <dest> <url>
/// Throws NotFoundError when a local source does not exist, Error on any
/// download/copy failure.
void fetch_to_file(const std::string& url, const std::filesystem::path& dest);

/// Fetch `url` fully into memory. Same URL handling as fetch_to_file.
std::vector<std::uint8_t> fetch_bytes(const std::string& url);

} // namespace lexe::http
