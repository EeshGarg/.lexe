// http — implementation. See http.hpp.

#include "core/http.hpp"
#include "core/error.hpp"
#include "core/util.hpp"

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

bool is_remote_url(const std::string& url) {
    return starts_with(url, "http://") || starts_with(url, "https://");
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
    if (starts_with(url, "file://")) return file_url_to_path(url);
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

void curl_fetch(const std::string& url, const fs::path& dest) {
    const auto result = lexe::util::run_process({
        "curl", "--fail", "-sS", "-L", "--max-time", "120",
        "--output", dest.string(), url,
    });
    if (result.exit_code != 0) {
        throw Error("download failed (curl exit " +
                    std::to_string(result.exit_code) + "): " + url);
    }
}

} // namespace

void fetch_to_file(const std::string& url, const fs::path& dest) {
    if (dest.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(dest.parent_path(), ec);
        if (ec) {
            throw Error("cannot create directory " + dest.parent_path().string() +
                        ": " + ec.message());
        }
    }
    if (is_remote_url(url)) {
        curl_fetch(url, dest);
        return;
    }
    const fs::path src = local_source(url);
    std::error_code ec;
    if (!fs::exists(src, ec) || fs::is_directory(src, ec)) {
        throw NotFoundError("source not found: " + url);
    }
    fs::copy_file(src, dest, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        throw Error("copy failed: " + src.string() + " -> " + dest.string() +
                    ": " + ec.message());
    }
}

std::vector<std::uint8_t> fetch_bytes(const std::string& url) {
    if (!is_remote_url(url)) {
        const fs::path src = local_source(url);
        std::error_code ec;
        if (!fs::exists(src, ec) || fs::is_directory(src, ec)) {
            throw NotFoundError("source not found: " + url);
        }
        return lexe::util::slurp(src);
    }
    const fs::path tmp = unique_temp_file();
    try {
        curl_fetch(url, tmp);
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
