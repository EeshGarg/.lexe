// integration — see integration.hpp (Definitive Architecture §14.1, §15.1).

#include "lexe/integration/integration.hpp"

#include "lexe/package/crypto.hpp"
#include "lexe/integration/desktop.hpp"
#include "lexe/integration/session.hpp"
#include "lexe/integration/session_manager.hpp"
#include "lexe/base/error.hpp"
#include "lexe/base/json_strict.hpp"
#include "lexe/runtime/launchref.hpp"
#include "lexe/base/limits.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/base/util.hpp"
#include "lexe/base/version.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <system_error>

namespace fs = std::filesystem;

namespace lexe {

namespace {

constexpr const char* kCanonicalMime = "application/vnd.usha.lexe";
constexpr const char* kLegacyMime = "application/x-lexe";
/// The one desktop entry that OWNS the `.lexe` type. Named for the handler
/// role, not for a binary, so the entry survives a frontend being renamed.
constexpr const char* kHandlerDesktopFile = "lexe-handler.desktop";
constexpr const char* kRuntimeMimeFile = "lexe.xml";

std::string sha256_of_file(const fs::path& file) {
    try {
        return crypto::sha256_file_hex(file);
    } catch (const std::exception&) {
        return {};
    }
}

/// The persistent `.lexe` MIME declaration. The canonical type is the one the
/// architecture names (§7 `application/vnd.usha.lexe`); the type the alpha
/// registered stays as an ALIAS so already-registered desktops, existing
/// mimeapps entries and previously-downloaded files keep resolving.
std::string runtime_mime_xml() {
    std::string xml;
    xml += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    xml += "<mime-info xmlns=\"http://www.freedesktop.org/standards/"
           "shared-mime-info\">\n";
    xml += std::string("  <mime-type type=\"") + kCanonicalMime + "\">\n";
    xml += "    <comment>.LEXE application</comment>\n";
    xml += std::string("    <alias type=\"") + kLegacyMime + "\"/>\n";
    // A .lexe is a signed ZIP container; declaring the parent type lets tools
    // that understand ZIP degrade gracefully instead of guessing.
    xml += "    <sub-class-of type=\"application/zip\"/>\n";
    xml += "    <glob pattern=\"*.lexe\"/>\n";
    xml += "    <icon name=\"application-vnd.usha.lexe\"/>\n";
    xml += "  </mime-type>\n";
    xml += "</mime-info>\n";
    return xml;
}

/// The persistent handler entry. `%f` (a single local file) is correct: the
/// handler opens ONE artifact and dispatches on its signed role.
std::string handler_desktop_entry() {
    std::string text;
    text += "[Desktop Entry]\n";
    text += "Type=Application\n";
    text += "Name=.LEXE\n";
    text += "GenericName=Application Manager\n";
    text += "Comment=Install, launch and manage .LEXE applications\n";
    text += "Exec=lexe-ui --open %f\n";
    text += "TryExec=lexe-ui\n";
    text += "Icon=lexe\n";
    text += "Terminal=false\n";
    // One MAIN category (System) plus an Additional one (PackageManager):
    // listing System AND Settings makes the entry appear twice in some menus.
    text += "Categories=System;PackageManager;\n";
    text += std::string("MimeType=") + kCanonicalMime + ";" + kLegacyMime +
            ";\n";
    text += "StartupNotify=true\n";
    text += "X-Lexe-Role=handler\n";
    return text;
}

/// Merge our default association into `mimeapps.list` without disturbing any
/// other association the user has. Returns true when the file now names our
/// handler as the default for the canonical type.
bool write_default_association(const fs::path& mimeapps) {
    // Parse the INI-ish file into ordered sections so unrelated user settings
    // are preserved byte-for-byte where possible.
    std::vector<std::pair<std::string, std::vector<std::string>>> sections;
    std::string current = "";
    sections.emplace_back(current, std::vector<std::string>{});

    std::error_code ec;
    if (fs::is_regular_file(mimeapps, ec)) {
        std::istringstream in(util::slurp_text(mimeapps));
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty() && line.front() == '[') {
                current = line;
                sections.emplace_back(current, std::vector<std::string>{});
            } else {
                sections.back().second.push_back(line);
            }
        }
    }

    const auto upsert = [&](const char* section_name, const char* mime) {
        auto it = std::find_if(sections.begin(), sections.end(),
                               [&](const auto& s) {
                                   return s.first == section_name;
                               });
        if (it == sections.end()) {
            sections.emplace_back(section_name, std::vector<std::string>{});
            it = std::prev(sections.end());
        }
        const std::string key = std::string(mime) + "=";
        const std::string value = key + kHandlerDesktopFile;
        for (std::string& existing : it->second) {
            if (existing.rfind(key, 0) == 0) {
                existing = value;
                return;
            }
        }
        it->second.push_back(value);
    };
    upsert("[Default Applications]", kCanonicalMime);
    upsert("[Default Applications]", kLegacyMime);

    std::string out;
    for (const auto& [name, lines] : sections) {
        if (!name.empty()) out += name + "\n";
        for (const std::string& line : lines) out += line + "\n";
    }
    try {
        fs::create_directories(mimeapps.parent_path(), ec);
        util::write_atomic(mimeapps, out);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

/// Package icons (FORMAT-0.1 §2 `icons/`) -> hicolor theme locations.
struct IconMapping {
    const char* source_name;
    const char* theme_subdir;
    const char* dest_ext;
};
constexpr IconMapping kIconMappings[] = {
    {"64.png", "64x64", ".png"},
    {"128.png", "128x128", ".png"},
    {"256.png", "256x256", ".png"},
    {"scalable.svg", "scalable", ".svg"},
};

/// How large an icon this runtime is willing to install into a shared theme.
///
/// A 256x256 PNG is a few tens of kilobytes; a scalable SVG is smaller still.
/// 4 MiB is generous for anything legitimate and small enough that a hostile
/// file cannot become a resource problem for whatever parses it next.
constexpr std::uintmax_t kMaxIconBytes = 4ull * 1024 * 1024;

/// Whether these bytes plausibly ARE the image kind the filename claims.
///
/// This is the one place a package's publisher-controlled bytes are handed to a
/// rich parser in a process that is NOT sandboxed. The application runs under
/// bubblewrap; its icon is installed into the user's hicolor theme, where the
/// desktop environment parses it -- gdk-pixbuf for PNG, librsvg for SVG -- in
/// the session's own process. Nothing validated those bytes at all: whatever a
/// package carried as `128.png` was written into the theme verbatim.
///
/// The bytes are hash-covered and signed, so this is a malicious-PUBLISHER
/// surface rather than a tampering one, and exploiting it needs a bug in the
/// desktop's image stack. That makes it cheap insurance rather than an
/// emergency -- which is the reason to take the cheap version: a magic-byte
/// check and a size cap, not an image decoder of our own. Adding a parser here
/// would add the very class of attack surface this is guarding.
///
/// A rejected icon is skipped, not fatal: an application with a strange icon
/// still installs and runs, and refusing the icon is strictly better than
/// shipping unvalidated bytes into a directory the desktop reads.
bool icon_content_is_plausible(const fs::path& file, bool is_svg) {
    std::error_code ec;
    const std::uintmax_t size = fs::file_size(file, ec);
    if (ec || size == 0 || size > kMaxIconBytes) return false;

    std::vector<std::uint8_t> head;
    try {
        head = util::slurp(file);
    } catch (const std::exception&) {
        return false;
    }
    if (head.size() > 1024) head.resize(1024);

    if (!is_svg) {
        // The 8-byte PNG signature (RFC 2083 §3.1). Deliberately exact: a file
        // that is not a PNG has no business being installed under a .png name,
        // whatever else it might be.
        static constexpr std::uint8_t kPng[8] = {0x89, 0x50, 0x4E, 0x47,
                                                0x0D, 0x0A, 0x1A, 0x0A};
        if (head.size() < sizeof(kPng)) return false;
        return std::equal(std::begin(kPng), std::end(kPng), head.begin());
    }

    // SVG is XML, so there is no magic number -- only a shape. Require the
    // first non-whitespace content to open an XML declaration, a comment, a
    // doctype, or an <svg> element. This rejects an ELF, a script, or a PNG
    // renamed to .svg, which is what the check is for; it is not an attempt to
    // decide whether the XML is valid.
    std::string text(head.begin(), head.end());
    const std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return false;
    text = text.substr(start);
    // A UTF-8 BOM is legal before an XML declaration.
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF) {
        text = text.substr(3);
        const std::size_t after = text.find_first_not_of(" \t\r\n");
        if (after == std::string::npos) return false;
        text = text.substr(after);
    }
    if (!(text.rfind("<?xml", 0) == 0 || text.rfind("<svg", 0) == 0 ||
          text.rfind("<!--", 0) == 0 || text.rfind("<!DOCTYPE", 0) == 0)) {
        return false;
    }

    // No internal DTD subset. This closes the gap the shape check above left,
    // and it left it in the most embarrassing way possible: the list of
    // acceptable openings included `<!DOCTYPE`, which is precisely the
    // construct that both SVG attacks need.
    //
    //   billion laughs   nested entity definitions that expand to gigabytes
    //   XXE              <!ENTITY x SYSTEM "file:///etc/passwd">
    //
    // librsvg is the consumer, in the session's own unsandboxed process, which
    // is the whole reason this validation exists. Modern librsvg and libxml2
    // cap entity expansion and refuse network entities, so this is a cheap
    // closure rather than an emergency -- but "the desktop's parser probably
    // defends itself" is not a reason for us to hand it the input.
    //
    // Searched over the whole file rather than the prefix: a DTD can follow
    // comments, and an icon is small enough that reading it twice costs
    // nothing. No legitimate SVG *icon* needs an internal DTD subset.
    std::string whole;
    try {
        const std::vector<std::uint8_t> bytes = util::slurp(file);
        whole.assign(bytes.begin(), bytes.end());
    } catch (const std::exception&) {
        return false;
    }
    return whole.find("<!DOCTYPE") == std::string::npos &&
           whole.find("<!ENTITY") == std::string::npos;
}

/// Whether this runtime is allowed to DELETE `file`.
///
/// `integration.json` records absolute paths, and it is local, unsigned state. A
/// removal that trusted those paths turned "can write one file inside LEXE_HOME"
/// into "delete any file this user can delete, at a moment the user chooses" --
/// and `doctor --repair` is precisely what somebody runs when their system is
/// already misbehaving. Demonstrated: two artifact records appended for an
/// application that was not installed, pointing at files in `$HOME`, and
/// `doctor --repair` deleted both and reported `Re-established 6 registration(s)`.
///
/// It does not cross a privilege boundary -- an attacker who can write that file
/// can usually write elsewhere -- and the likelier route is not malice at all: a
/// truncated or garbled record with a mangled path reaches the same `remove`.
/// What makes it worth confining is that HARDENING.md already names the rule it
/// broke. Its single-source table assigns *"filesystem ownership ('may Lexe
/// delete this?')"* to the registry and names the anti-pattern outright: *"direct
/// `remove_all` on computed paths"*. This was a `remove` on a path read from a
/// file, with no owner consulted.
///
/// So deletion is confined to the five directories this runtime writes into. A
/// record naming anything else is not silently obeyed and not silently ignored:
/// it is REPORTED, because an artifact record pointing outside the tree is
/// itself a finding.
bool may_delete_impl(const Paths& paths, const fs::path& file) {
    std::error_code ec;
    const fs::path resolved = fs::weakly_canonical(file, ec);
    const fs::path candidate = ec ? file : resolved;
    for (const fs::path& root : {paths.applications_dir(), paths.icons_dir(),
                                 paths.mime_dir(), paths.launch_dir(),
                                 paths.systemd_user_dir()}) {
        std::error_code root_ec;
        const fs::path canonical_root = fs::weakly_canonical(root, root_ec);
        const fs::path base = root_ec ? root : canonical_root;
        const fs::path relative = candidate.lexically_relative(base);
        if (relative.empty() || relative == fs::path("..")) continue;
        if (relative.begin() != relative.end() &&
            relative.begin()->string() == "..") {
            continue;
        }
        return true;
    }
    return false;
}

std::string icon_name(const std::string& id) { return "lexe-" + id; }

} // namespace

// Exported so every reader of recorded absolute paths asks the same question.
// The predicate above was written for `integration.json`; `installation.json`'s
// `createdFiles` is the same kind of state read by a different module, and the
// uninstall sweep there had no guard at all. See integration.hpp.
bool may_delete(const Paths& paths, const fs::path& file) {
    return may_delete_impl(paths, file);
}

const char* to_string(ArtifactKind k) {
    switch (k) {
    case ArtifactKind::RuntimeMime: return "runtime-mime";
    case ArtifactKind::RuntimeHandler: return "runtime-handler";
    case ArtifactKind::AppDesktopEntry: return "app-desktop-entry";
    case ArtifactKind::AppIcon: return "app-icon";
    case ArtifactKind::AppMimeTypes: return "app-mime-types";
    case ArtifactKind::LaunchReference: return "launch-reference";
    case ArtifactKind::SessionUnit: return "session-unit";
    }
    return "runtime-mime";
}

bool artifact_kind_from_string(const std::string& text, ArtifactKind& out) {
    static const struct {
        const char* name;
        ArtifactKind kind;
    } kKinds[] = {
        {"runtime-mime", ArtifactKind::RuntimeMime},
        {"runtime-handler", ArtifactKind::RuntimeHandler},
        {"app-desktop-entry", ArtifactKind::AppDesktopEntry},
        {"app-icon", ArtifactKind::AppIcon},
        {"app-mime-types", ArtifactKind::AppMimeTypes},
        {"launch-reference", ArtifactKind::LaunchReference},
        {"session-unit", ArtifactKind::SessionUnit},
    };
    for (const auto& k : kKinds) {
        if (text == k.name) {
            out = k.kind;
            return true;
        }
    }
    return false;
}

const char* to_string(ArtifactHealth h) {
    switch (h) {
    case ArtifactHealth::Ok: return "ok";
    case ArtifactHealth::Missing: return "missing";
    case ArtifactHealth::Modified: return "modified";
    }
    return "ok";
}

std::size_t IntegrationReport::problem_count() const {
    std::size_t problems = unregistered_apps.size() + orphaned.size();
    for (const ArtifactCheck& check : checks) {
        if (check.health != ArtifactHealth::Ok) ++problems;
    }
    return problems;
}

// ------------------------------------------------------------ state file

IntegrationState IntegrationState::load(const Paths& paths) {
    IntegrationState state;
    state.runtime_version = version::runtime_string();
    const fs::path file = paths.integration_state_file();
    std::error_code ec;
    if (!fs::is_regular_file(file, ec)) return state;

    try {
        const nlohmann::json doc = json_strict::parse(
            util::slurp_text(file), "integration state",
            limits::kMaxHashesBytes);
        if (!doc.is_object()) return state;
        if (const auto it = doc.find("schema");
            it != doc.end() && it->is_string()) {
            state.schema = it->get<std::string>();
        }
        if (const auto it = doc.find("runtimeVersion");
            it != doc.end() && it->is_string()) {
            state.runtime_version = it->get<std::string>();
        }
        if (const auto it = doc.find("updatedAt");
            it != doc.end() && it->is_string()) {
            state.updated_at = it->get<std::string>();
        }
        const auto artifacts = doc.find("artifacts");
        if (artifacts == doc.end() || !artifacts->is_array()) return state;
        for (const nlohmann::json& element : *artifacts) {
            if (!element.is_object()) continue;
            IntegrationArtifact artifact;
            if (const auto it = element.find("kind");
                it != element.end() && it->is_string()) {
                if (!artifact_kind_from_string(it->get<std::string>(),
                                               artifact.kind)) {
                    continue; // an artifact kind this runtime does not know
                }
            }
            if (const auto it = element.find("path");
                it != element.end() && it->is_string()) {
                artifact.path = it->get<std::string>();
            }
            if (const auto it = element.find("sha256");
                it != element.end() && it->is_string()) {
                artifact.sha256 = it->get<std::string>();
            }
            if (const auto it = element.find("app");
                it != element.end() && it->is_string()) {
                artifact.owner_app = it->get<std::string>();
            }
            if (artifact.path.empty()) continue;
            state.artifacts.push_back(std::move(artifact));
        }
    } catch (const std::exception&) {
        // A corrupt state file must not block repair: treat it as empty and
        // let repair() re-register everything from installed state.
        state.artifacts.clear();
    }
    return state;
}

std::string IntegrationState::to_json() const {
    nlohmann::ordered_json doc;
    doc["schema"] = schema;
    doc["runtimeVersion"] = runtime_version;
    doc["updatedAt"] = updated_at;
    nlohmann::ordered_json list = nlohmann::ordered_json::array();
    for (const IntegrationArtifact& artifact : artifacts) {
        nlohmann::ordered_json element;
        element["kind"] = to_string(artifact.kind);
        element["path"] = artifact.path;
        element["sha256"] = artifact.sha256;
        element["app"] = artifact.owner_app;
        list.push_back(std::move(element));
    }
    doc["artifacts"] = std::move(list);
    return doc.dump(2) + "\n";
}

void IntegrationState::save(const Paths& paths) const {
    IntegrationState copy = *this;
    copy.updated_at = util::now_utc_string();
    copy.runtime_version = version::runtime_string();
    std::error_code ec;
    fs::create_directories(paths.home(), ec);
    util::write_atomic(paths.integration_state_file(), copy.to_json());
}

void IntegrationState::replace_scope(
    const std::string& app_id,
    const std::vector<IntegrationArtifact>& replacement) {
    artifacts.erase(std::remove_if(artifacts.begin(), artifacts.end(),
                                   [&](const IntegrationArtifact& a) {
                                       return a.owner_app == app_id;
                                   }),
                    artifacts.end());
    artifacts.insert(artifacts.end(), replacement.begin(), replacement.end());
}

std::vector<IntegrationArtifact>
IntegrationState::scope(const std::string& app_id) const {
    std::vector<IntegrationArtifact> out;
    for (const IntegrationArtifact& a : artifacts) {
        if (a.owner_app == app_id) out.push_back(a);
    }
    return out;
}

// ------------------------------------------------------ DesktopIntegration

DesktopIntegration::DesktopIntegration(const Paths& paths) : paths_(paths) {}

const char* DesktopIntegration::canonical_mime_type() { return kCanonicalMime; }
const char* DesktopIntegration::legacy_mime_type() { return kLegacyMime; }

void refresh_desktop_databases(const Paths& paths) {
#ifndef _WIN32
    // A confined layout is read by no desktop, so there is no cache to keep
    // current. Running the tools against `<LEXE_HOME>/mime` builds a cache
    // nobody consults and makes update-mime-database print its "not in the
    // search path set by XDG_DATA_HOME and XDG_DATA_DIRS" advice — onto the
    // same terminal where `lexe integrate` is reporting what it wrote, and
    // into the output of every test that registers anything.
    if (paths.desktop_scope() != DesktopScope::xdg) return;

    // Best effort: these tools rebuild the desktop's caches. Their absence or
    // failure is not an integration failure — the files we wrote are the
    // durable state; the caches are derived.
    // Resolved to an ABSOLUTE path first, deliberately.
    //
    // Spawning by bare name makes libc search PATH itself, and on a WSL host
    // PATH carries 36 Windows directories on a DrvFS mount where a failed stat
    // costs milliseconds. Two tools that are usually absent therefore cost ~550
    // failed stats: `lexe doctor` was measured at 1001 ms against 33 ms with a
    // clean PATH, and every scripted invocation paid it.
    //
    // find_on_path with skip_foreign_mounts does the lookup once, over the
    // directories that could actually hold a Linux desktop tool. A tool that is
    // not found is simply not run, which was already the contract: these rebuild
    // derived caches, and their absence is not an integration failure.
    //
    // This is the third instance of the identical defect -- the launcher hunting
    // terminal emulators, provider discovery hunting emulators, and now this.
    // The shape to watch for is a lookup that EXPECTS to miss.
    for (const std::vector<std::string>& argv :
         {std::vector<std::string>{"update-desktop-database",
                                   paths.applications_dir().string()},
          std::vector<std::string>{"update-mime-database",
                                   paths.mime_dir().string()}}) {
        const std::string tool =
            util::find_on_path(argv.front(), /*skip_foreign_mounts=*/true);
        if (tool.empty()) continue; // absent: nothing to rebuild, by contract
        std::vector<std::string> resolved = argv;
        resolved.front() = tool;
        try {
            (void)util::run_process(resolved);
        } catch (const std::exception&) {
            // ignored by design
        }
    }
#else
    (void)paths;
#endif
}

IntegrationReport DesktopIntegration::install_runtime_handler() {
    IntegrationReport report;
    IntegrationState state = IntegrationState::load(paths_);

    const fs::path mime_file = paths_.mime_dir() / "packages" / kRuntimeMimeFile;
    const fs::path handler_file =
        paths_.applications_dir() / kHandlerDesktopFile;

    std::vector<IntegrationArtifact> runtime_artifacts;
    try {
        util::spit(mime_file, std::string_view(runtime_mime_xml()));
        runtime_artifacts.push_back({ArtifactKind::RuntimeMime,
                                     mime_file.string(),
                                     sha256_of_file(mime_file), ""});

        util::spit(handler_file, std::string_view(handler_desktop_entry()));
        runtime_artifacts.push_back({ArtifactKind::RuntimeHandler,
                                     handler_file.string(),
                                     sha256_of_file(handler_file), ""});
    } catch (const std::exception& e) {
        report.unrepaired.push_back(std::string("runtime handler: ") + e.what());
        return report;
    }

    // The association itself. Without this, which program owns `.lexe` is
    // whatever the session decided — exactly the alpha's reboot failure.
    if (write_default_association(paths_.mimeapps_file())) {
        report.notes.push_back(
            std::string(kCanonicalMime) + " is registered to " +
            kHandlerDesktopFile + " in " + paths_.mimeapps_file().string());
    } else {
        report.unrepaired.push_back(
            "could not write the default .lexe association to " +
            paths_.mimeapps_file().string());
    }

    state.replace_scope("", runtime_artifacts);
    state.save(paths_);
    refresh_desktop_databases(paths_);

    report.ok = report.unrepaired.empty();
    for (const IntegrationArtifact& a : runtime_artifacts) {
        report.checks.push_back({a, ArtifactHealth::Ok, "written"});
    }
    return report;
}

IntegrationReport
DesktopIntegration::install_app(const Manifest& manifest,
                                const fs::path& icons_source_dir) {
    IntegrationReport report;
    validate_app_id(manifest.id, "integration");
    IntegrationState state = IntegrationState::load(paths_);
    std::vector<IntegrationArtifact> artifacts;

    try {
        if (manifest.integration_desktop_entry) {
            const fs::path entry = paths_.applications_dir() /
                                   (icon_name(manifest.id) + ".desktop");
            util::spit(entry,
                       std::string_view(desktop::desktop_entry_text(manifest)));
            artifacts.push_back({ArtifactKind::AppDesktopEntry, entry.string(),
                                 sha256_of_file(entry), manifest.id});
        }

        bool wrote_any_icon = false;
        for (const IconMapping& mapping : kIconMappings) {
            const fs::path source = icons_source_dir / mapping.source_name;
            std::error_code ec;
            if (!fs::is_regular_file(source, ec)) continue;
            // Validated before it is written where the desktop will parse it.
            // See icon_content_is_plausible: the application is sandboxed, its
            // icon is not.
            if (!icon_content_is_plausible(
                    source, std::string_view(mapping.dest_ext) == ".svg")) {
                report.notes.push_back(
                    std::string("skipped the icon ") + mapping.source_name +
                    ": it is not a plausible " +
                    (std::string_view(mapping.dest_ext) == ".svg" ? "SVG"
                                                                  : "PNG") +
                    ", or exceeds the size this runtime installs");
                continue;
            }
            const fs::path destination =
                paths_.icons_dir() / mapping.theme_subdir / "apps" /
                (icon_name(manifest.id) + mapping.dest_ext);
            util::spit(destination, util::slurp(source));
            artifacts.push_back({ArtifactKind::AppIcon, destination.string(),
                                 sha256_of_file(destination), manifest.id});
            wrote_any_icon = true;
        }
        if (!wrote_any_icon) {
            // No icon SOURCE is available (an application installed by an
            // earlier runtime that did not retain its icons). Carry forward
            // whatever icon registrations already exist on disk instead of
            // dropping them: replace_scope() below rewrites this application's
            // whole scope, so anything omitted here would be silently
            // DE-REGISTERED — its later loss would become undetectable, and
            // uninstall would leave the files behind. Never forget an artifact
            // merely because it cannot be regenerated right now.
            for (const IntegrationArtifact& existing : state.scope(manifest.id)) {
                if (existing.kind != ArtifactKind::AppIcon) continue;
                std::error_code ec;
                if (fs::is_regular_file(fs::path(existing.path), ec)) {
                    artifacts.push_back(existing);
                }
            }
        }

        if (!manifest.file_associations.empty()) {
            const fs::path mime_file = paths_.mime_dir() / "packages" /
                                       (icon_name(manifest.id) + ".xml");
            util::spit(mime_file,
                       std::string_view(desktop::mime_xml_text(manifest)));
            artifacts.push_back({ArtifactKind::AppMimeTypes, mime_file.string(),
                                 sha256_of_file(mime_file), manifest.id});
        }

        // The two CONDITIONAL artifacts, carried forward when their condition
        // has gone false but the file is still on disk.
        //
        // `AppDesktopEntry` and `AppMimeTypes` are written only when the manifest
        // asks for them, and `replace_scope` below rewrites this application's
        // whole scope -- so an update that flips `integration.desktopEntry` to
        // false, or drops its `fileAssociations`, dropped the RECORD while
        // leaving the file in the desktop's directories. `AppIcon` and
        // `SessionUnit` already had this branch; these two did not.
        //
        // What that cost is narrower than it looks, and worth stating precisely:
        // uninstall removes the files anyway, so they are not left behind
        // forever. What was lost is DETECTION -- `lexe doctor` reported "healthy"
        // while two untracked files sat in the desktop's directories, which is
        // the one guarantee integration.json exists to provide -- and a stale
        // menu entry plus a stale MIME association outlived the update that
        // removed them, so the desktop honoured a declaration the application no
        // longer made.
        //
        // Carried forward rather than deleted here, deliberately: this function
        // registers, and making it also retract would give one function two
        // jobs. The record keeps them visible to `doctor`, which is what the
        // user needs in order to decide.
        for (const IntegrationArtifact& existing : state.scope(manifest.id)) {
            const bool conditional =
                existing.kind == ArtifactKind::AppDesktopEntry ||
                existing.kind == ArtifactKind::AppMimeTypes;
            if (!conditional) continue;
            const bool already_listed =
                std::any_of(artifacts.begin(), artifacts.end(),
                            [&](const IntegrationArtifact& a) {
                                return a.kind == existing.kind;
                            });
            if (already_listed) continue;
            std::error_code ec;
            if (!fs::is_regular_file(fs::path(existing.path), ec)) continue;
            artifacts.push_back(existing);
            report.notes.push_back(
                std::string("kept tracking ") + to_string(existing.kind) + " " +
                existing.path +
                ": this version no longer declares it, but the file is still "
                "present and an untracked file is an undetectable one");
        }

        // §15.1 — the first-class launch artifact. This is what makes
        // "double-click run.lexe" a supported path instead of the user being
        // handed a raw ELF.
        const fs::path run_lexe = create_launch_reference(paths_, manifest);
        artifacts.push_back({ArtifactKind::LaunchReference, run_lexe.string(),
                             sha256_of_file(run_lexe), manifest.id});

        // A systemd `--user` unit, if one was ever enabled for this application
        // (docs/SERVICES.md). Carried forward here rather than created here,
        // and the distinction is the whole design:
        //
        //   the unit FILE is regenerated when it has gone missing or drifted,
        //   because that is an artifact .LEXE wrote and can write again
        //
        //   whether the unit is ENABLED is never touched, because that is a
        //   decision the user made, and a repair that silently re-enabled what
        //   somebody had deliberately disabled would be overruling them under
        //   the name of fixing them
        //
        // So nothing below calls systemctl. `replace_scope` rewrites this
        // application's whole scope, so an existing record must be carried
        // forward explicitly or it would be DE-REGISTERED — the same hazard the
        // icon branch above documents, and the reason uninstall would then leave
        // a unit behind for a service that no longer exists.
        for (const IntegrationArtifact& existing : state.scope(manifest.id)) {
            if (existing.kind != ArtifactKind::SessionUnit) continue;
            IntegrationArtifact carried = existing;
            const fs::path unit(existing.path);
            std::error_code unit_ec;
            if (!fs::is_regular_file(unit, unit_ec) ||
                sha256_of_file(unit) != existing.sha256) {
                // Regenerate it. The unit must name the runtime absolutely
                // (a systemd --user unit inherits no PATH), and if this process
                // cannot say where it lives, the honest outcome is a reported
                // failure rather than a unit written with a guess.
                const std::optional<fs::path> self = util::self_executable();
                if (!self.has_value()) {
                    report.unrepaired.push_back(
                        "cannot regenerate the service unit " + existing.path +
                        ": the path of the running lexe binary is unknown");
                } else {
                    try {
                        session::UnitInputs inputs;
                        inputs.manifest = manifest;
                        inputs.runtime_path = self->string();
                        if (const std::optional<std::string> home =
                                util::get_env("LEXE_HOME");
                            home.has_value() && !home->empty()) {
                            inputs.lexe_home = *home;
                        }
                        util::write_atomic(
                            unit, std::string_view(session::unit_text(inputs)));
                        carried.sha256 = sha256_of_file(unit);
                        report.notes.push_back("regenerated the service unit " +
                                               existing.path);
                    } catch (const std::exception& e) {
                        report.unrepaired.push_back(
                            "cannot regenerate the service unit " +
                            existing.path + ": " + e.what());
                    }
                }
            }
            artifacts.push_back(carried);
        }
    } catch (const std::exception& e) {
        report.unrepaired.push_back(std::string("integration for ") +
                                    manifest.id + ": " + e.what());
    }

    state.replace_scope(manifest.id, artifacts);
    state.save(paths_);
    refresh_desktop_databases(paths_);

    for (const IntegrationArtifact& a : artifacts) {
        report.checks.push_back({a, ArtifactHealth::Ok, "written"});
    }
    report.ok = report.unrepaired.empty();
    return report;
}

void DesktopIntegration::remove_runtime_handler() {
    IntegrationState state = IntegrationState::load(paths_);
    std::error_code ec;
    for (const IntegrationArtifact& artifact : state.scope("")) {
        fs::remove(fs::path(artifact.path), ec);
    }
    state.replace_scope("", {});
    state.save(paths_);

    // Drop only OUR default association, leaving every other association the
    // user has set exactly as it was.
    if (fs::is_regular_file(paths_.mimeapps_file(), ec)) {
        std::istringstream in(util::slurp_text(paths_.mimeapps_file()));
        std::string line;
        std::string out;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            const bool ours =
                line == std::string(kCanonicalMime) + "=" +
                            kHandlerDesktopFile ||
                line == std::string(kLegacyMime) + "=" + kHandlerDesktopFile;
            if (!ours) out += line + "\n";
        }
        try {
            util::write_atomic(paths_.mimeapps_file(), out);
        } catch (const std::exception&) {
            // Leaving a stale association is better than losing the file.
        }
    }
    refresh_desktop_databases(paths_);
}

void DesktopIntegration::remove_app(const std::string& id) {
    IntegrationState state = IntegrationState::load(paths_);

    // A service unit is RETRACTED, not merely deleted, and it goes first.
    //
    // Every other artifact here is a file that means nothing once it is gone.
    // A unit is also a registration inside systemd: `enable` left a symlink in
    // `default.target.wants`, and unlinking the unit alone leaves systemd
    // wanting a service whose file no longer exists — it logs a failure at every
    // login and `systemctl --user status` reports "not-found" for an application
    // that was uninstalled cleanly. So this asks the session manager to stop,
    // disable and remove it, which is the only code that knows the full
    // retraction, and it runs BEFORE the state file is rewritten because that is
    // where it reads the unit's recorded path from.
    for (const IntegrationArtifact& artifact : state.scope(id)) {
        if (artifact.kind != ArtifactKind::SessionUnit) continue;
        try {
            session::make_session_manager(paths_)->disable(id);
        } catch (const std::exception&) {
            // Deliberately swallowed: this is the removal path, and a session
            // manager that cannot be reached must not be able to block an
            // uninstall. The file removal below is the fallback, and what it
            // cannot clean up -- the enablement symlink -- `lexe doctor`
            // reports, because the unit will then be recorded nowhere and
            // present nowhere while systemd still wants it.
        }
        break;
    }

    state = IntegrationState::load(paths_); // disable() may have rewritten it
    std::error_code ec;
    for (const IntegrationArtifact& artifact : state.scope(id)) {
        const fs::path file(artifact.path);
        if (!may_delete(paths_, file)) {
            // Deliberately not deleted, and deliberately not silent. See
            // may_delete: a recorded path is not a licence to remove a file.
            outside_tree_.push_back(artifact.path);
            continue;
        }
        fs::remove(file, ec); // missing is fine
    }
    state.replace_scope(id, {});
    state.save(paths_);
    refresh_desktop_databases(paths_);
}

IntegrationReport
DesktopIntegration::check_state(const IntegrationState& state) const {
    IntegrationReport report;
    std::error_code ec;

    for (const IntegrationArtifact& artifact : state.artifacts) {
        ArtifactCheck check;
        check.artifact = artifact;
        const fs::path path(artifact.path);
        // A record naming a path this runtime would never write is a finding in
        // its own right: either the state file is damaged, or something put it
        // there. It is reported rather than acted upon — see may_delete.
        if (!may_delete(paths_, path)) {
            check.health = ArtifactHealth::Modified;
            check.detail = "this record names a path outside the directories "
                           ".LEXE writes; it will not be repaired or removed";
            report.checks.push_back(std::move(check));
            report.unrepaired.push_back(
                "refusing to act on a recorded path outside the runtime's own "
                "directories: " + artifact.path);
            continue;
        }
        if (!fs::is_regular_file(path, ec)) {
            check.health = ArtifactHealth::Missing;
            check.detail = "not present on disk";
        } else if (!artifact.sha256.empty() &&
                   sha256_of_file(path) != artifact.sha256) {
            check.health = ArtifactHealth::Modified;
            check.detail = "content differs from what .LEXE wrote";
        } else {
            check.health = ArtifactHealth::Ok;
            check.detail = "present";
        }
        report.checks.push_back(std::move(check));
    }

    // Applications installed but not registered — the state file was lost, or
    // they were installed by a runtime that did not record integration.
    const Registry registry(paths_);
    std::vector<std::string> installed;
    try {
        installed = registry.list_installed();
    } catch (const std::exception&) {
        // A missing apps/ directory simply means nothing is installed.
    }
    for (const std::string& id : installed) {
        if (state.scope(id).empty()) report.unregistered_apps.push_back(id);
    }

    // Registrations owned by applications that are gone.
    for (const IntegrationArtifact& artifact : state.artifacts) {
        if (artifact.owner_app.empty()) continue;
        if (std::find(installed.begin(), installed.end(),
                      artifact.owner_app) == installed.end()) {
            report.orphaned.push_back(artifact.path);
        }
    }

    // The runtime handler must exist at all, or nothing opens `.lexe` files.
    const bool has_handler =
        std::any_of(state.artifacts.begin(), state.artifacts.end(),
                    [](const IntegrationArtifact& a) {
                        return a.kind == ArtifactKind::RuntimeHandler;
                    });
    if (!has_handler) {
        IntegrationArtifact expected{
            ArtifactKind::RuntimeHandler,
            (paths_.applications_dir() / kHandlerDesktopFile).string(), "", ""};
        report.checks.push_back(
            {expected, ArtifactHealth::Missing,
             "the .LEXE handler is not registered on this machine"});
    }

    // The default association is the piece that actually survives a reboot.
    {
        bool associated = false;
        if (fs::is_regular_file(paths_.mimeapps_file(), ec)) {
            const std::string text = util::slurp_text(paths_.mimeapps_file());
            associated =
                text.find(std::string(kCanonicalMime) + "=" +
                          kHandlerDesktopFile) != std::string::npos;
        }
        if (!associated) {
            IntegrationArtifact expected{ArtifactKind::RuntimeHandler,
                                         paths_.mimeapps_file().string(), "",
                                         ""};
            report.checks.push_back(
                {expected, ArtifactHealth::Missing,
                 std::string("no persistent default association for ") +
                     kCanonicalMime});
        } else {
            report.notes.push_back(
                std::string("default association for ") + kCanonicalMime +
                " -> " + kHandlerDesktopFile);
        }
    }

    report.ok = report.problem_count() == 0;
    return report;
}

IntegrationReport DesktopIntegration::verify() const {
    return check_state(IntegrationState::load(paths_));
}

IntegrationReport DesktopIntegration::repair() {
    IntegrationReport before = verify();
    if (before.ok) {
        before.notes.push_back("nothing to repair");
        return before;
    }

    IntegrationReport after;
    after.notes = before.notes;

    // 1. The runtime handler and the durable association, unconditionally:
    //    they are cheap, idempotent, and the root of every other path.
    const IntegrationReport runtime = install_runtime_handler();
    for (const std::string& problem : runtime.unrepaired) {
        after.unrepaired.push_back(problem);
    }
    for (const ArtifactCheck& check : runtime.checks) {
        after.repaired.push_back(check.artifact.path);
    }

    // 2. Drop registrations owned by applications that are no longer here.
    {
        IntegrationState state = IntegrationState::load(paths_);
        const Registry registry(paths_);
        std::vector<std::string> installed;
        try {
            installed = registry.list_installed();
        } catch (const std::exception&) {
        }
        std::vector<std::string> stale_apps;
        for (const IntegrationArtifact& artifact : state.artifacts) {
            if (artifact.owner_app.empty()) continue;
            if (std::find(installed.begin(), installed.end(),
                          artifact.owner_app) == installed.end() &&
                std::find(stale_apps.begin(), stale_apps.end(),
                          artifact.owner_app) == stale_apps.end()) {
                stale_apps.push_back(artifact.owner_app);
            }
        }
        for (const std::string& id : stale_apps) {
            remove_app(id);
            after.notes.push_back("removed stale integration for " + id);
        }
    }

    // 3. Re-establish every installed application's integration FROM INSTALLED
    //    STATE — the stored manifest copy, not the original package. This is
    //    what makes integration repairable after a reboot, a cache wipe, or a
    //    desktop that dropped its associations: no .lexe file is needed.
    const Registry registry(paths_);
    std::vector<std::string> installed;
    try {
        installed = registry.list_installed();
    } catch (const std::exception&) {
    }
    for (const std::string& id : installed) {
        try {
            const Manifest manifest = registry.read_manifest(id);
            // The package is long gone by now, so icons come from the RETAINED
            // per-version copy in the meta store (installer.cpp writes it
            // there precisely so repair has a source). For an application
            // installed by an earlier runtime that directory does not exist;
            // install_app() then carries the existing registrations forward
            // rather than dropping them.
            const std::string version = registry.current_version(id);
            const fs::path icons = registry.meta_dir(id, version) / "icons";
            const IntegrationReport app = install_app(manifest, icons);
            for (const ArtifactCheck& check : app.checks) {
                after.repaired.push_back(check.artifact.path);
            }
            for (const std::string& problem : app.unrepaired) {
                after.unrepaired.push_back(problem);
            }
        } catch (const std::exception& e) {
            after.unrepaired.push_back("could not re-register " + id + ": " +
                                       e.what());
        }
    }

    for (const std::string& path : outside_tree_) {
        after.unrepaired.push_back(
            "refused to delete a recorded path outside the runtime's own "
            "directories: " + path);
    }
    outside_tree_.clear();

    const IntegrationReport confirm = verify();
    after.checks = confirm.checks;
    after.unregistered_apps = confirm.unregistered_apps;
    after.orphaned = confirm.orphaned;
    after.ok = confirm.ok && after.unrepaired.empty();
    return after;
}

} // namespace lexe
