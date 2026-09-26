// identity — the App ID and version rules (base/identity.hpp).

#include "lexe/base/identity.hpp"

#include "lexe/base/error.hpp"

#include <string_view>

namespace lexe {

namespace {

bool id_segment_ok(std::string_view segment) {
    if (segment.empty()) return false;
    for (const char c : segment) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-';
        if (!ok) return false;
    }
    return true;
}

} // namespace

bool app_id_is_valid(const std::string& id) {
    bool ok = !id.empty() && id.size() <= 255;
    std::size_t segments = 0;
    std::size_t start = 0;
    while (ok) {
        const std::size_t dot = id.find('.', start);
        const std::size_t end = (dot == std::string::npos) ? id.size() : dot;
        ok = id_segment_ok(std::string_view(id).substr(start, end - start));
        ++segments;
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return ok && segments >= 2;
}

void validate_app_id(const std::string& id, const char* context) {
    if (!app_id_is_valid(id)) {
        throw Error(std::string(context) + ": invalid application id: \"" + id +
                    "\"");
    }
}

bool version_string_is_valid(const std::string& version) {
    if (version.empty() || version.size() > 64) return false;
    if (version == "." || version == "..") return false;
    for (const unsigned char c : version) {
        // Space and every control character: not representable in current.txt,
        // which is read back trimmed, and meaningless in a path component.
        if (c <= 0x20 || c == 0x7F) return false;
        if (c == '/' || c == '\\' || c == ':') return false;
    }
    return true;
}

void validate_version_string(const std::string& version, const char* context) {
    if (!version_string_is_valid(version)) {
        throw Error(std::string(context) + ": invalid version string: \"" +
                    version + "\"");
    }
}

} // namespace lexe
