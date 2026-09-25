// integration — see integration.hpp (Definitive Architecture §14.1, §15.1).

#include "core/integration.hpp"

#include "core/crypto.hpp"
#include "core/desktop.hpp"
#include "core/error.hpp"
#include "core/json_strict.hpp"
#include "core/launchref.hpp"
#include "core/limits.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"
#include "core/version.hpp"

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

std::string icon_name(const std::string& id) { return "lexe-" + id; }

} // namespace

const char* to_string(ArtifactKind k) {
    switch (k) {
    case ArtifactKind::RuntimeMime: return "runtime-mime";
    case ArtifactKind::RuntimeHandler: return "runtime-handler";
    case ArtifactKind::AppDesktopEntry: return "app-desktop-entry";
    case ArtifactKind::AppIcon: return "app-icon";
    case ArtifactKind::AppMimeTypes: return "app-mime-types";
    case ArtifactKind::LaunchReference: return "launch-reference";
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
    // Best effort: these tools rebuild the desktop's caches. Their absence or
    // failure is not an integration failure — the files we wrote are the
    // durable state; the caches are derived.
    for (const std::vector<std::string>& argv :
         {std::vector<std::string>{"update-desktop-database",
                                   paths.applications_dir().string()},
          std::vector<std::string>{"update-mime-database",
                                   paths.mime_dir().string()}}) {
        try {
            (void)util::run_process(argv);
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

        for (const IconMapping& mapping : kIconMappings) {
            const fs::path source = icons_source_dir / mapping.source_name;
            std::error_code ec;
            if (!fs::is_regular_file(source, ec)) continue;
            const fs::path destination =
                paths_.icons_dir() / mapping.theme_subdir / "apps" /
                (icon_name(manifest.id) + mapping.dest_ext);
            util::spit(destination, util::slurp(source));
            artifacts.push_back({ArtifactKind::AppIcon, destination.string(),
                                 sha256_of_file(destination), manifest.id});
        }

        if (!manifest.file_associations.empty()) {
            const fs::path mime_file = paths_.mime_dir() / "packages" /
                                       (icon_name(manifest.id) + ".xml");
            util::spit(mime_file,
                       std::string_view(desktop::mime_xml_text(manifest)));
            artifacts.push_back({ArtifactKind::AppMimeTypes, mime_file.string(),
                                 sha256_of_file(mime_file), manifest.id});
        }

        // §15.1 — the first-class launch artifact. This is what makes
        // "double-click run.lexe" a supported path instead of the user being
        // handed a raw ELF.
        const fs::path run_lexe = create_launch_reference(paths_, manifest);
        artifacts.push_back({ArtifactKind::LaunchReference, run_lexe.string(),
                             sha256_of_file(run_lexe), manifest.id});
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
    std::error_code ec;
    for (const IntegrationArtifact& artifact : state.scope(id)) {
        fs::remove(fs::path(artifact.path), ec); // missing is fine
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
            // Icons were copied into the hicolor theme at install time; the
            // package is long gone, so re-copy from the version directory's
            // icons/ when it exists and otherwise keep what is already there.
            const std::string version = registry.current_version(id);
            const fs::path icons =
                registry.version_dir(id, version) / "icons";
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

    const IntegrationReport confirm = verify();
    after.checks = confirm.checks;
    after.unregistered_apps = confirm.unregistered_apps;
    after.orphaned = confirm.orphaned;
    after.ok = confirm.ok && after.unrepaired.empty();
    return after;
}

} // namespace lexe
