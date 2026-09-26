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

/// Refuse a URL whose transport cannot protect the request.
///
/// FORMAT-0.1 §7 says an update manifest URL is `https://`. The reader accepted
/// `http://` identically, and `curl -L` followed redirects without restricting
/// the scheme, so even an https URL could be downgraded by the server.
///
/// Authenticity does not depend on the transport -- every update document is
/// signature-pinned to the installed publisher key -- so this is not what stops
/// a forged update. It matters for the two things a signature cannot give:
///
///   confidentiality  an observer otherwise learns which applications and
///                    which versions a user runs
///   freshness        §7.1's freeze attack is undefended, and over plaintext it
///                    becomes available to anyone on the path rather than only
///                    to whoever operates the source
///
/// `file://` and plain paths are unaffected: they have no transport to protect,
/// and they are what the test suite uses.
///
/// Throws Error naming the URL when the scheme is plaintext HTTP.
void require_secure_url(const std::string& url);

/// How large a response this fetch is willing to accept, in bytes.
///
/// A REQUIRED argument rather than an optional cap, because the caller is the
/// only one who knows, and the default of "no limit" was the defect: the
/// updater enforced `update.json`'s 1 MiB budget only when PARSING, so a
/// hostile server could serve 256 MiB, have it read into memory in full, and
/// the first complaint was about the signature. Unbounded allocation before
/// anything is authenticated.
///
/// Enforced twice, on purpose: `--max-filesize` so curl aborts the transfer,
/// and a check on the received file so a source that lies about its length (or
/// a local `file://` path, which curl never sees) cannot get past it either.
struct Limit {
    std::uint64_t max_bytes;
};

/// Download `url` to `dest` (parent directories are created; an existing file
/// is overwritten). curl invocation:
///   curl --fail -sS -L --proto-redir =https --max-time 120
///        --max-filesize <limit> --output <dest> <url>
/// Throws NotFoundError when a local source does not exist, Error on any
/// download/copy failure, and Error when the response exceeds `limit`.
void fetch_to_file(const std::string& url, const std::filesystem::path& dest,
                   Limit limit);

/// Fetch `url` fully into memory, refusing anything larger than `limit`.
/// Same URL handling as fetch_to_file.
std::vector<std::uint8_t> fetch_bytes(const std::string& url, Limit limit);

} // namespace lexe::http
