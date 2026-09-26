// http — implementation. See http.hpp.

#include "lexe/base/http.hpp"
#include "lexe/base/error.hpp"
#include "lexe/base/util.hpp"

#include <cctype>
#include <chrono>
#include <random>
#include <system_error>

namespace fs = std::filesystem;

namespace lexe::http {

namespace {

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

/// The scheme, lowercased, or empty when the URL has none.
///
/// RFC 3986 §3.1 makes a scheme case-insensitive, so `HTTPS://` is a perfectly
/// valid https URL. Both of the functions below used to compare a lowercase
/// prefix directly, which meant `HTTPS://…` was not recognised as remote and
/// was silently treated as a FILESYSTEM PATH -- a publisher who wrote it in a
/// manifest got a permanently broken update channel and "source not found".
///
/// Worse, it meant the plaintext refusal was *accidentally* safe: `HTTP://`
/// slipped past the refusal AND past the remote check, so nothing fetched it.
/// Two independent functions sharing one bug is not a security property; making
/// either of them correct on its own would have re-enabled plaintext fetches.
std::string scheme_of(const std::string& url) {
    const std::size_t colon = url.find("://");
    if (colon == std::string::npos) return {};
    std::string scheme = url.substr(0, colon);
    for (char& ch : scheme) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + 32);
    }
    return scheme;
}

bool is_remote_url(const std::string& url) {
    const std::string scheme = scheme_of(url);
    return scheme == "http" || scheme == "https";
}

std::string percent_decode(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() &&
            std::isxdigit(static_cast<unsigned char>(s[i + 1])) != 0 &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2])) != 0) {
            const auto byte = lexe::util::hex_decode(s.substr(i + 1, 2));
            out.push_back(static_cast<char>(byte[0]));
            i += 2;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

// Convert a file:// URL to a local filesystem path (RFC 8089 subset).
fs::path file_url_to_path(const std::string& url) {
    std::string_view rest{url};
    rest.remove_prefix(7); // "file://"
    if (starts_with(rest, "localhost/")) {
        rest.remove_prefix(std::string_view("localhost").size());
    }
    std::string decoded = percent_decode(rest);
#ifdef _WIN32
    // "file:///C:/dir/file" decodes to "/C:/dir/file" — drop the leading '/'.
    if (decoded.size() >= 3 && decoded[0] == '/' &&
        std::isalpha(static_cast<unsigned char>(decoded[1])) != 0 &&
        decoded[2] == ':') {
        decoded.erase(0, 1);
    }
#endif
    // Interpret the decoded bytes as UTF-8.
    return fs::path(std::u8string(decoded.begin(), decoded.end()));
}

// Resolve a non-remote source (file:// URL or plain path) to a local path.
fs::path local_source(const std::string& url) {
    if (scheme_of(url) == "file") return file_url_to_path(url);
    return fs::path(std::u8string(url.begin(), url.end()));
}

fs::path unique_temp_file() {
    static std::mt19937_64 rng(
        static_cast<std::uint64_t>(std::random_device{}()) ^
        static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    return fs::temp_directory_path() /
           ("lexe-fetch-" + std::to_string(rng()) + ".tmp");
}

/// Refuse a file larger than the caller's limit.
///
/// Applied to the RECEIVED file, not to a declared length: a server can lie
/// about Content-Length, and a `file://` source never goes through curl at all.
void enforce_limit(const fs::path& file, const std::string& url,
                   std::uint64_t max_bytes) {
    std::error_code ec;
    const auto size = fs::file_size(file, ec);
    if (ec) {
        throw Error("cannot determine the size of the fetched " + url + ": " +
                    ec.message());
    }
    if (size > max_bytes) {
        throw Error("refusing " + url + ": " + std::to_string(size) +
                        " bytes exceeds the " + std::to_string(max_bytes) +
                        "-byte limit for this document",
                    "A source serving more than the format allows for this "
                    "document is either broken or hostile. Nothing from it has "
                    "been parsed or trusted.");
    }
}

void curl_fetch(const std::string& url, const fs::path& dest,
                std::uint64_t max_bytes) {
    const auto result = lexe::util::run_process({
        "curl", "--fail", "-sS", "-L",
        // A redirect MUST NOT be able to downgrade the transport. `-L` follows
        // redirects, and without this an `https://` URL could be redirected to
        // plaintext by the server -- which makes the §7.1 freeze attack
        // available to anyone on the path, not only the source operator.
        "--proto-redir", "=https",
        "--max-time", "120",
        // Abort the transfer rather than read it and complain afterwards. curl
        // honours this against Content-Length and against the running total.
        "--max-filesize", std::to_string(max_bytes),
        "--output", dest.string(), url,
    });
    if (result.exit_code != 0) {
        // 63 is CURLE_FILESIZE_EXCEEDED; saying which limit was hit is the
        // difference between an actionable error and "curl exit 63".
        if (result.exit_code == 63) {
            throw Error("refusing " + url + ": the response exceeds the " +
                            std::to_string(max_bytes) +
                            "-byte limit for this document",
                        "A source serving more than the format allows for this "
                        "document is either broken or hostile. Nothing from it "
                        "has been parsed or trusted.");
        }
        throw Error("download failed (curl exit " +
                    std::to_string(result.exit_code) + "): " + url);
    }
    enforce_limit(dest, url, max_bytes);
}

} // namespace

void require_secure_url(const std::string& url) {
    // An ALLOWLIST, not a denylist, and the shape matters more than the
    // contents. This was a denylist on a lowercase `http://` prefix, which
    // missed `HTTP://` -- and a denylist on a string prefix is exactly the
    // shape that produces that class of miss. An allowlist fails closed for
    // every scheme nobody has thought about yet.
    const std::string scheme = scheme_of(url);
    if (scheme.empty() || scheme == "file" || scheme == "https") return;
    if (scheme == "http") {
        throw Error("refusing a plaintext http:// source: " + url,
                    "Format 0.1 requires an https:// update source. A "
                    "signature proves who wrote an update, not that you are "
                    "being told about the newest one -- over plaintext, anyone "
                    "on the path can hold you at an older signed version. Use "
                    "https://, or a file:// path for local testing.");
    }
    throw Error("refusing an update source with the \"" + scheme +
                    "\" scheme: " + url,
                "An update source must be an https:// URL, a file:// URL, or a "
                "filesystem path.");
}

void fetch_to_file(const std::string& url, const fs::path& dest,
                   Limit limit) {
    if (dest.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(dest.parent_path(), ec);
        if (ec) {
            throw Error("cannot create directory " + dest.parent_path().string() +
                        ": " + ec.message());
        }
    }
    if (is_remote_url(url)) {
        require_secure_url(url);
        curl_fetch(url, dest, limit.max_bytes);
        return;
    }
    const fs::path src = local_source(url);
    std::error_code ec;
    if (!fs::exists(src, ec) || fs::is_directory(src, ec)) {
        throw NotFoundError(
            "source not found: " + url,
            "Check the update source URL; change it with `lexe source set "
            "<id> <url>`.");
    }
    // Checked BEFORE copying: a local source can be a 256 MiB file just as
    // easily as a remote one, and copying it first would spend the bytes the
    // limit exists to save.
    enforce_limit(src, url, limit.max_bytes);
    fs::copy_file(src, dest, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        throw Error("copy failed: " + src.string() + " -> " + dest.string() +
                    ": " + ec.message());
    }
}

std::vector<std::uint8_t> fetch_bytes(const std::string& url, Limit limit) {
    if (!is_remote_url(url)) {
        const fs::path src = local_source(url);
        std::error_code ec;
        if (!fs::exists(src, ec) || fs::is_directory(src, ec)) {
            throw NotFoundError(
            "source not found: " + url,
            "Check the update source URL; change it with `lexe source set "
            "<id> <url>`.");
        }
        enforce_limit(src, url, limit.max_bytes);
        return lexe::util::slurp(src);
    }
    require_secure_url(url);
    const fs::path tmp = unique_temp_file();
    try {
        curl_fetch(url, tmp, limit.max_bytes);
        auto bytes = lexe::util::slurp(tmp);
        std::error_code ec;
        fs::remove(tmp, ec);
        return bytes;
    } catch (...) {
        std::error_code ec;
        fs::remove(tmp, ec);
        throw;
    }
}

} // namespace lexe::http
