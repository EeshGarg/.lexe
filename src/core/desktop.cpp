// desktop — Linux desktop integration (FORMAT-0.1 §9, SPEC "Installed
// Application Representation"): `.desktop` entries whose Exec line is always
// `lexe run <id>` (never a version-specific path), hicolor icons, MIME XML,
// best-effort `update-desktop-database` / `update-mime-database` via
// run_process (no shell — security invariant #3).
//
// On Windows (development host) every function is a recorded no-op that
// returns `skipped` — but it still computes the exact list of files it
// WOULD create, so installation.json records are testable anywhere.

#include "core/desktop.hpp"
#include "core/util.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

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

/// Package icons (FORMAT-0.1 §2 `icons/`) → hicolor theme locations.
struct IconMapping {
    const char* source_name;  // name inside the package's icons/ dir
    const char* theme_subdir; // hicolor size directory
    const char* dest_ext;     // destination extension
};
constexpr std::array<IconMapping, 4> kIconMappings{{
    {"64.png", "64x64", ".png"},
    {"128.png", "128x128", ".png"},
    {"256.png", "256x256", ".png"},
    {"scalable.svg", "scalable", ".svg"},
}};

/// Everything integrate_app would write. Computed identically on all
/// platforms; Linux executes it, Windows only reports it.
struct AppPlan {
    std::optional<fs::path> desktop_file;
    std::vector<std::pair<fs::path, fs::path>> icons; // source → destination
    std::optional<fs::path> mime_file;

    std::vector<std::string> created_files() const {
        std::vector<std::string> files;
        if (desktop_file.has_value()) files.push_back(desktop_file->string());
        for (const auto& icon : icons) files.push_back(icon.second.string());
        if (mime_file.has_value()) files.push_back(mime_file->string());
        return files;
    }
};

AppPlan plan_app(const Paths& paths, const Manifest& manifest,
                 const fs::path& icons_source_dir) {
    AppPlan plan;
    if (manifest.integration_desktop_entry) {
        plan.desktop_file =
            paths.applications_dir() / (icon_name(manifest.id) + ".desktop");
    }
    for (const auto& mapping : kIconMappings) {
        const fs::path source = icons_source_dir / mapping.source_name;
        std::error_code ec;
        if (fs::is_regular_file(source, ec)) {
            plan.icons.emplace_back(
                source, paths.icons_dir() / mapping.theme_subdir / "apps" /
                            (icon_name(manifest.id) + mapping.dest_ext));
        }
    }
    if (!manifest.file_associations.empty()) {
        plan.mime_file =
            paths.mime_dir() / "packages" / (icon_name(manifest.id) + ".xml");
    }
    return plan;
}

#ifndef _WIN32
/// Best-effort database refresh; the tools may be absent or fail — neither
/// is an error (ARCHITECTURE.md: "failures of the refresh tools are not
/// errors").
void refresh_databases(const Paths& paths, bool desktop_changed,
                       bool mime_changed) {
    if (desktop_changed) {
        try {
            (void)util::run_process(
                {"update-desktop-database", paths.applications_dir().string()});
        } catch (const std::exception&) {
            // best effort
        }
    }
    if (mime_changed) {
        try {
            (void)util::run_process(
                {"update-mime-database", paths.mime_dir().string()});
        } catch (const std::exception&) {
            // best effort
        }
    }
}
#endif

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

std::string runtime_desktop_entry_text() {
    return "[Desktop Entry]\n"
           "Type=Application\n"
           "Name=Lexe Installer\n"
           "Comment=Install Lexe application packages\n"
           "Exec=lexe-installer %f\n"
           "Icon=lexe\n"
           "Terminal=false\n"
           "NoDisplay=true\n"
           "Categories=System;PackageManager;\n"
           "MimeType=application/x-lexe;\n";
}

std::string runtime_mime_xml_text() {
    return mime_info_document(
        {{"application/x-lexe", {"*.lexe"}}},
        "Lexe application package");
}

IntegrationResult integrate_app(const Paths& paths, const Manifest& manifest,
                                const fs::path& icons_source_dir) {
    const AppPlan plan = plan_app(paths, manifest, icons_source_dir);
    IntegrationResult result;
    result.created_files = plan.created_files();
#ifdef _WIN32
    // Recorded no-op on the development host: report what a Linux host would
    // have created so installation.json stays testable, write nothing.
    result.status = IntegrationStatus::skipped;
#else
    if (plan.desktop_file.has_value()) {
        util::spit(*plan.desktop_file,
                   std::string_view(desktop_entry_text(manifest)));
    }
    for (const auto& [source, destination] : plan.icons) {
        util::spit(destination, util::slurp(source)); // creates parent dirs
    }
    if (plan.mime_file.has_value()) {
        util::spit(*plan.mime_file, std::string_view(mime_xml_text(manifest)));
    }
    refresh_databases(paths, plan.desktop_file.has_value(),
                      plan.mime_file.has_value());
    result.status = IntegrationStatus::applied;
#endif
    return result;
}

void remove_integration(const Paths& paths,
                        const std::vector<std::string>& created_files) {
#ifdef _WIN32
    // Recorded no-op on Windows: integration never created anything.
    (void)paths;
    (void)created_files;
#else
    for (const auto& file : created_files) {
        std::error_code ec;
        fs::remove(fs::path(file), ec); // missing files are ignored
    }
    refresh_databases(paths, true, true);
#endif
}

IntegrationResult integrate_runtime(const Paths& paths) {
    const fs::path desktop_file =
        paths.applications_dir() / "lexe-installer.desktop";
    const fs::path mime_file = paths.mime_dir() / "packages" / "lexe.xml";

    IntegrationResult result;
    result.created_files = {desktop_file.string(), mime_file.string()};
#ifdef _WIN32
    result.status = IntegrationStatus::skipped;
#else
    util::spit(desktop_file, std::string_view(runtime_desktop_entry_text()));
    util::spit(mime_file, std::string_view(runtime_mime_xml_text()));
    refresh_databases(paths, true, true);
    result.status = IntegrationStatus::applied;
#endif
    return result;
}

} // namespace lexe::desktop
