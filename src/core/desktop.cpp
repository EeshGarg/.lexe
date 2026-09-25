// desktop — the `.desktop` and shared-mime-info DOCUMENTS an installed
// application is registered with (FORMAT-0.1 §9, SPEC "Installed Application
// Representation"). Pure content generation only: every string here is a
// function of the manifest, computed identically on every platform and
// testable as a string anywhere.
//
// WRITING these documents, registering them, recording them and repairing them
// is `DesktopIntegration` (core/integration.hpp) and belongs to it alone. This
// module used to own a second copy of that machinery — it planned files, wrote
// them, refreshed the freedesktop databases and registered the runtime handler
// under a MIME type that is no longer the one the runtime claims. Two engines
// for one job is how the alpha ended up with registrations that depended on
// which implementation ran last. There is one now.

#include "core/desktop.hpp"

#include <algorithm>
#include <string_view>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace lexe::desktop {

namespace {

/// Freedesktop icon (and .desktop basename) namespace for Lexe-managed apps.
std::string icon_name(const std::string& id) { return "lexe-" + id; }

/// Desktop Entry value escaping: the spec recognises \n \t \r and \\ escape
/// sequences inside values; literal newlines are not allowed.
std::string desktop_escape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char c : value) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\t': out += "\\t"; break;
        case '\r': out += "\\r"; break;
        default: out += c; break;
        }
    }
    return out;
}

/// Element of a semicolon-separated Desktop Entry list value: additionally
/// escapes embedded ';' as "\;".
std::string desktop_escape_list_element(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char c : desktop_escape(value)) {
        if (c == ';') out += "\\;";
        else out += c;
    }
    return out;
}

/// Minimal XML escaping, safe for both text nodes and attribute values.
std::string xml_escape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char c : value) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&apos;"; break;
        default: out += c; break;
        }
    }
    return out;
}

/// shared-mime-info document from (type, patterns) groups.
std::string mime_info_document(
    const std::vector<std::pair<std::string, std::vector<std::string>>>& types,
    const std::string& comment) {
    std::string xml;
    xml += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    xml += "<mime-info xmlns=\"http://www.freedesktop.org/standards/"
           "shared-mime-info\">\n";
    for (const auto& [type, patterns] : types) {
        xml += "  <mime-type type=\"" + xml_escape(type) + "\">\n";
        xml += "    <comment>" + xml_escape(comment) + "</comment>\n";
        for (const auto& pattern : patterns) {
            xml += "    <glob pattern=\"" + xml_escape(pattern) + "\"/>\n";
        }
        xml += "  </mime-type>\n";
    }
    xml += "</mime-info>\n";
    return xml;
}

} // namespace

std::string desktop_entry_text(const Manifest& manifest) {
    std::string text;
    text += "[Desktop Entry]\n";
    text += "Type=Application\n";
    text += "Name=" + desktop_escape(manifest.name) + "\n";
    // Stable Lexe launcher — never a version-specific path (SPEC "Installed
    // Application Representation", FORMAT-0.1 §9).
    text += "Exec=lexe run " + manifest.id + "\n";
    text += "Icon=" + icon_name(manifest.id) + "\n";
    text += "Terminal=false\n";
    if (!manifest.categories.empty()) {
        text += "Categories=";
        for (const auto& category : manifest.categories) {
            text += desktop_escape_list_element(category) + ";";
        }
        text += "\n";
    }
    std::vector<std::string> mime_types;
    for (const auto& fa : manifest.file_associations) {
        if (std::find(mime_types.begin(), mime_types.end(), fa.mime_type) ==
            mime_types.end()) {
            mime_types.push_back(fa.mime_type);
        }
    }
    if (!mime_types.empty()) {
        text += "MimeType=";
        for (const auto& mime : mime_types) {
            text += desktop_escape_list_element(mime) + ";";
        }
        text += "\n";
    }
    text += "X-Lexe-Id=" + manifest.id + "\n";
    return text;
}

std::string mime_xml_text(const Manifest& manifest) {
    // Group fileAssociations by mimeType, preserving first-appearance order;
    // each extension becomes a "*<.ext>" glob (a missing leading dot is
    // tolerated and normalised).
    std::vector<std::pair<std::string, std::vector<std::string>>> types;
    for (const auto& fa : manifest.file_associations) {
        std::string pattern;
        if (!fa.extension.empty() && fa.extension.front() == '.') {
            pattern = "*" + fa.extension;
        } else {
            pattern = "*." + fa.extension;
        }
        auto it = std::find_if(types.begin(), types.end(), [&](const auto& t) {
            return t.first == fa.mime_type;
        });
        if (it == types.end()) {
            types.emplace_back(fa.mime_type, std::vector<std::string>{pattern});
        } else if (std::find(it->second.begin(), it->second.end(), pattern) ==
                   it->second.end()) {
            it->second.push_back(pattern);
        }
    }
    return mime_info_document(types, manifest.name + " document");
}

} // namespace lexe::desktop
