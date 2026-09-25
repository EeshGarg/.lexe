// lexe-builder — GTK 3 graphical developer app (ARCHITECTURE.md #GUI, sibling
// of lexe-installer). "Drop your app files into a folder, fill in a few
// fields, click Build, get a signed .lexe."
//
// Flow: choose an "App files folder" (its CONTENTS become payload/) -> fill in
// App ID, Name, Version, Entrypoint (a file discovered in the folder),
// Publisher name, architectures and optional permissions -> choose a signing
// key (generate a fresh one, or point at an existing key file) -> pick an
// output path -> Build. The build constructs a FORMAT-0.1 §5 manifest from the
// form, packs the folder with PackageWriter (§1), and verifies the result
// (§6). The manifest's publisher.publicKey is ALWAYS the signing key's public
// key — the developer never types a key.
//
// The file has two layers, exactly like src/gui/main.cpp:
//  * `lexe::gui` — pure, GTK-free presentation/validation logic (the "view
//    model"), unit-tested on every platform by tests/test_builder.cpp (which
//    defines LEXE_GUI_VIEWMODEL_ONLY before including this file);
//  * the GTK 3 application itself, compiled only when <gtk/gtk.h> is available
//    — the Linux-only `lexe-builder` CMake target.
//
// The GUI links lexe_core directly and shells out to nothing. The build runs
// OFF the UI thread (g_thread_new); the worker touches no GTK API and reports
// back via g_idle_add. No C++ exception is ever allowed to cross the C
// callback boundary — the worker catches everything and reports failure.

#if !defined(LEXE_GUI_VIEWMODEL_ONLY)
#if defined(__has_include)
#if !__has_include(<gtk/gtk.h>)
#define LEXE_GUI_VIEWMODEL_ONLY 1
#endif
#else
#define LEXE_GUI_VIEWMODEL_ONLY 1
#endif
#endif

#include "core/buildreport.hpp"
#include "core/compat.hpp"
#include "core/depengine.hpp"
#include "core/elf.hpp"
#include "core/paths.hpp"
#include "core/runtime_profile.hpp"
#include "core/settings.hpp"
#include "core/tux32.hpp"
#include "core/util.hpp"

#if !defined(LEXE_GUI_VIEWMODEL_ONLY)
#include "gui/style.hpp"
#endif
#include "core/version.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace lexe::gui {

// ---------------------------------------------------------------------------
// Pure presentation/validation logic — everything the builder window needs to
// decide and to emit, as plain values. No GTK types anywhere, so this layer is
// unit-testable on hosts without GTK (the Windows dev host).
// ---------------------------------------------------------------------------

/// Every field the builder form collects, as plain values. `available_entrypoints`
/// is the set of regular files found in the chosen folder (relative, '/'-joined);
/// the chosen `entrypoint` must be one of them.
struct BuilderForm {
    std::string app_id;
    std::string name;
    std::string version = "1.0.0";
    std::string entrypoint;
    std::string publisher_name;
    std::string publisher_website; // optional
    bool arch_x86_64 = true;
    bool arch_aarch64 = false;
    bool perm_network = false;
    bool perm_user_files_selected = false;
    std::vector<std::string> available_entrypoints;
    // Phase 2 wizard additions (all optional; defaults keep prior behavior).
    std::string description;                 // forward-compatible, informational
    std::vector<std::string> categories;     // freedesktop categories
    RuntimeProfile profile = RuntimeProfile::CorePortable; // target profile
    std::uint64_t payload_size_bytes = 0;    // for install.estimatedSize
    bool bundle_icons = false;               // an icons/ folder is present to ship
};

/// Result of validate_form(): a pass, or the first human-readable reason the
/// form cannot be built.
struct ValidationResult {
    bool ok = false;
    std::string error;
};

/// FORMAT-0.1 §5 reverse-DNS shape check: 2+ dot-separated segments of
/// [a-zA-Z0-9-]+, at most 255 characters. Mirrors manifest.cpp validate_id but
/// returns a bool so the form can reject early with a friendly message.
inline bool is_reverse_dns_id(const std::string& id) {
    if (id.empty() || id.size() > 255) return false;
    std::size_t segment_count = 0;
    std::size_t segment_length = 0;
    for (const char c : id) {
        if (c == '.') {
            if (segment_length == 0) return false; // empty segment
            ++segment_count;
            segment_length = 0;
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-') {
            ++segment_length;
        } else {
            return false;
        }
    }
    if (segment_length == 0) return false; // trailing dot
    ++segment_count;
    return segment_count >= 2;
}

/// The architectures the form selected, in canonical order.
inline std::vector<std::string> selected_architectures(const BuilderForm& form) {
    std::vector<std::string> architectures;
    if (form.arch_x86_64) architectures.push_back("x86_64");
    if (form.arch_aarch64) architectures.push_back("aarch64");
    return architectures;
}

/// The permissions the form selected (FORMAT-0.1 §5, informational in 0.1).
inline std::vector<std::string> selected_permissions(const BuilderForm& form) {
    std::vector<std::string> permissions;
    if (form.perm_network) permissions.push_back("network");
    if (form.perm_user_files_selected) {
        permissions.push_back("user-files-selected");
    }
    return permissions;
}

/// Validate the form before any file work. Checks the required fields, the
/// reverse-DNS id shape, that a selected entrypoint really is a file in the
/// chosen folder, and that at least one architecture is selected. The signing
/// key is resolved separately (it needs file IO/crypto) — see the GTK layer.
inline ValidationResult validate_form(const BuilderForm& form) {
    ValidationResult result;
    if (form.app_id.empty()) {
        result.error = "App ID is required (reverse-DNS, e.g. com.example.app).";
        return result;
    }
    if (!is_reverse_dns_id(form.app_id)) {
        result.error =
            "App ID must be reverse-DNS: two or more dot-separated segments of "
            "letters, digits or hyphens (e.g. com.example.app).";
        return result;
    }
    if (form.name.empty()) {
        result.error = "Name is required.";
        return result;
    }
    if (form.version.empty()) {
        result.error = "Version is required.";
        return result;
    }
    if (form.publisher_name.empty()) {
        result.error = "Publisher name is required.";
        return result;
    }
    if (form.entrypoint.empty()) {
        result.error =
            "Choose an entrypoint — the file inside the folder that starts the "
            "application.";
        return result;
    }
    if (std::find(form.available_entrypoints.begin(),
                  form.available_entrypoints.end(),
                  form.entrypoint) == form.available_entrypoints.end()) {
        result.error = "The chosen entrypoint \"" + form.entrypoint +
                       "\" is not a file in the selected folder.";
        return result;
    }
    if (selected_architectures(form).empty()) {
        result.error = "Select at least one architecture (x86_64 or aarch64).";
        return result;
    }
    result.ok = true;
    return result;
}

/// Build the FORMAT-0.1 §5 `lexe.json` text from the form and the resolved
/// signing-key public key (publisher.publicKey is ALWAYS the signing key). The
/// result is a valid 0.1 manifest and round-trips through Manifest::parse.
inline std::string build_manifest_json(const BuilderForm& form,
                                       const std::string& public_key) {
    nlohmann::ordered_json doc;
    doc["lexeVersion"] = "0.1";
    doc["id"] = form.app_id;
    doc["name"] = form.name;
    doc["version"] = form.version;

    nlohmann::ordered_json publisher;
    publisher["name"] = form.publisher_name;
    if (!form.publisher_website.empty()) {
        publisher["website"] = form.publisher_website;
    }
    publisher["publicKey"] = public_key;
    doc["publisher"] = std::move(publisher);

    doc["applicationType"] = "native";
    doc["architectures"] = selected_architectures(form);

    nlohmann::ordered_json entrypoint;
    entrypoint["executable"] = form.entrypoint;
    entrypoint["arguments"] = nlohmann::ordered_json::array();
    doc["entrypoint"] = std::move(entrypoint);

    nlohmann::ordered_json install;
    install["scope"] = "user";
    install["mode"] = "bundled";
    if (form.payload_size_bytes > 0) {
        install["estimatedSize"] = form.payload_size_bytes;
    }
    doc["install"] = std::move(install);

    const std::vector<std::string> permissions = selected_permissions(form);
    if (!permissions.empty()) {
        doc["permissions"] = permissions;
    }
    // Record the profile this build was GATED on. Without it every reader
    // re-judged the package against Core Portable, so a package deliberately
    // built as Native Capture — host-locked by definition — came back from
    // `lexe inspect` as a hard portability failure, from the same runtime whose
    // Builder had just accepted it. Optional and forward-compatible: older
    // runtimes ignore the field (FORMAT-0.1 §5).
    doc["runtimeProfile"] = lexe::to_string(form.profile);
    // Optional freedesktop categories (integration §9).
    if (!form.categories.empty()) {
        nlohmann::ordered_json integration;
        integration["categories"] = form.categories;
        doc["integration"] = std::move(integration);
    }
    // A short description is forward-compatible metadata (ignored by 0.1 parse).
    if (!form.description.empty()) {
        doc["description"] = form.description;
    }

    return doc.dump(2) + "\n";
}

/// Enumerate the regular files under `folder`, as relative '/'-joined paths,
/// sorted lexicographically. These are the candidate entrypoints (the folder's
/// contents become payload/). A missing/unreadable folder yields an empty list
/// rather than throwing.
inline std::vector<std::string> enumerate_entrypoints(
    const std::filesystem::path& folder) {
    std::vector<std::string> files;
    std::error_code ec;
    if (!std::filesystem::is_directory(folder, ec)) return files;
    std::filesystem::recursive_directory_iterator it(
        folder, std::filesystem::directory_options::skip_permission_denied, ec);
    const std::filesystem::recursive_directory_iterator end;
    for (; !ec && it != end; it.increment(ec)) {
        std::error_code fec;
        if (!std::filesystem::is_regular_file(it->path(), fec) || fec) continue;
        const std::filesystem::path rel =
            std::filesystem::relative(it->path(), folder, fec);
        if (fec || rel.empty()) continue;
        files.push_back(rel.generic_string());
    }
    std::sort(files.begin(), files.end());
    files.erase(std::unique(files.begin(), files.end()), files.end());
    return files;
}

// ---------------------------------------------------------------------------
// Phase 2 wizard model (DX1): steps, automatic source detection, and the
// dependency-review rows. All GTK-free and unit-tested.
// ---------------------------------------------------------------------------

/// The wizard's ordered steps (the default developer workflow).
enum class WizardStep {
    Source,        // 1. select source
    Dependencies,  // 2. review detected dependencies
    Architecture,  // 3. select supported architectures
    Metadata,      // 4. configure installer metadata
    Signing,       // 5. sign application
    Output,        // 6. select output
    Build,         // 7. build
};

struct WizardStepInfo {
    WizardStep step;
    std::string title;
    std::string subtitle;
};

inline const std::vector<WizardStepInfo>& wizard_steps() {
    static const std::vector<WizardStepInfo> kSteps = {
        {WizardStep::Source, "Source", "Choose your application's files"},
        {WizardStep::Dependencies, "Dependencies",
         "Review automatically detected dependencies"},
        {WizardStep::Architecture, "Architecture",
         "Select supported architectures"},
        {WizardStep::Metadata, "Installer",
         "Name, publisher, icon, categories and permissions"},
        {WizardStep::Signing, "Signing", "Sign the application"},
        {WizardStep::Output, "Output", "Choose the output package"},
        {WizardStep::Build, "Build", "Build, sign and verify"},
    };
    return kSteps;
}

/// One reviewed dependency, in plain words: what it is and how to handle it.
struct DependencyRow {
    std::string soname;
    std::string handling;       // "host-interface" / "bundle" / "forbidden" / …
    std::string reason;         // why it was classified this way
    std::string recommendation; // recommended handling
    bool warn = false;          // forbidden / unresolved → highlight
};

inline std::vector<DependencyRow> dependency_rows(const DependencyReport& r) {
    std::vector<DependencyRow> rows;
    for (const Dependency& d : r.dependencies) {
        DependencyRow row;
        row.soname = d.soname;
        row.handling = to_string(d.kind);
        row.reason = d.reason;
        row.recommendation = d.recommendation;
        row.warn = d.kind == DependencyKind::Forbidden ||
                   d.kind == DependencyKind::Unresolved;
        rows.push_back(std::move(row));
    }
    return rows;
}

/// Everything automatically detected from a source folder (Step 1).
struct SourceDetection {
    bool ok = false;                       // a runnable main executable was found
    std::string summary;                   // friendly one-line summary
    std::string main_executable;           // relative entrypoint ("" if none)
    std::string executable_type;           // "executable ELF (x86_64, dynamic)"
    std::string detected_arch;             // "x86_64" / "aarch64" / ""
    std::vector<std::string> entrypoints;  // candidate files (relative)
    std::vector<std::string> icons;        // detected icon files present
    std::uint64_t payload_size = 0;        // total bytes under the folder
    DependencyReport dependencies;         // analysis of the main executable
};

/// Total size of regular files under `folder` (bounded, best-effort).
inline std::uint64_t folder_size(const std::filesystem::path& folder) {
    std::uint64_t total = 0;
    std::error_code ec;
    for (auto it = std::filesystem::recursive_directory_iterator(
             folder, std::filesystem::directory_options::skip_permission_denied, ec);
         it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
        std::error_code fec;
        if (it->is_regular_file(fec) && !fec) {
            total += static_cast<std::uint64_t>(it->file_size(fec));
        }
    }
    return total;
}

/// Automatically inspect a source folder: find the main executable, its
/// architecture and type, candidate entrypoints, icons, and the full dependency
/// graph. Never throws; ok is false when no runnable executable is found.
inline SourceDetection detect_source(const std::filesystem::path& folder) {
    SourceDetection d;
    d.entrypoints = enumerate_entrypoints(folder);
    d.payload_size = folder_size(folder);

    std::error_code ec;
    std::filesystem::path main;
    for (const std::string& rel : d.entrypoints) {
        const std::filesystem::path p = folder / rel;
        const elf::ElfInfo info = elf::read(p);
        if (info.is_elf && info.has_interpreter) {
            main = p;
            d.main_executable = rel;
            d.detected_arch = info.arch();
            d.executable_type =
                std::string(elf::to_string(info.type)) + " ELF (" +
                (d.detected_arch.empty() ? "unknown arch" : d.detected_arch) +
                (info.dynamically_linked() ? ", dynamically linked" : "") + ")";
            break;
        }
    }

    for (const char* icon : {"64.png", "128.png", "256.png", "scalable.svg"}) {
        if (std::filesystem::is_regular_file(folder / icon, ec) ||
            std::filesystem::is_regular_file(folder / "icons" / icon, ec)) {
            d.icons.push_back(icon);
        }
    }

    if (!main.empty()) {
        DependencyOptions opts;
        opts.payload_search_paths.push_back(folder);
        for (auto it = std::filesystem::recursive_directory_iterator(
                 folder, std::filesystem::directory_options::skip_permission_denied, ec);
             it != std::filesystem::recursive_directory_iterator();
             it.increment(ec)) {
            std::error_code dec;
            if (it->is_directory(dec) && !dec) {
                opts.payload_search_paths.push_back(it->path());
            }
        }
        d.dependencies = analyze_dependencies(main, opts);
    }

    d.ok = !d.main_executable.empty();
    if (d.ok) {
        d.summary = "Detected " + d.executable_type + " \"" + d.main_executable +
                    "\" with " +
                    std::to_string(d.dependencies.dependencies.size()) +
                    " dependency(ies).";
    } else if (d.entrypoints.empty()) {
        d.summary = "This folder is empty or unreadable.";
    } else {
        d.summary = "No native executable detected — choose the entrypoint "
                    "manually (a script or interpreted app is fine).";
    }
    return d;
}

/// The Build gate for a chosen runtime profile, given the analyzed source.
/// Core Portable is HARD-gated on Tux32 Core 1: a non-conformant dependency
/// closure BLOCKS the build (build_allowed=false), because Core Portable is the
/// profile that makes a cross-distribution portability claim. Forward Runtime
/// and Native Capture always allow the build but are clearly labeled — forward
/// compatibility is advisory, and native capture is explicitly host-locked.
struct ProfileGate {
    bool build_allowed = true; // may the Build proceed?
    bool blocking = false;     // Build is disabled because of a hard failure
    std::string headline;      // one-line status
    std::string detail;        // human explanation
    std::vector<std::string> notes;         // advisory lines to surface
    std::optional<Core1VerifyResult> core1; // set for Core Portable only
};

inline ProfileGate evaluate_profile_gate(RuntimeProfile profile,
                                         const DependencyReport& deps) {
    ProfileGate g;
    const RuntimeProfileInfo& info = runtime_profile_info(profile);
    switch (profile) {
    case RuntimeProfile::CorePortable: {
        const Core1VerifyResult r = verify_against_profile(deps, tux32_core_1());
        g.core1 = r;
        g.build_allowed = r.conformant();
        g.blocking = !r.conformant();
        g.detail = r.detail;
        g.headline = r.conformant()
                         ? "Core Portable — conformant with Tux32 " + r.profile_id
                         : "Core Portable — NOT conformant (" +
                               std::string(to_string(r.verdict)) + ")";
        for (const Core1Offender& o : r.symbol_offenders) {
            g.notes.push_back(o.object + " requires " + o.version +
                              " — above the " + r.glibc_ceiling + " ceiling");
        }
        for (const std::string& s : r.forbidden) {
            g.notes.push_back("forbidden host interface: " + s +
                              " (must be host-provided, not bundled)");
        }
        for (const std::string& s : r.unresolved) {
            g.notes.push_back("unresolved dependency: " + s +
                              " (bundle it or confirm the host provides it)");
        }
        for (const std::string& n : r.notes) g.notes.push_back(n);
        break;
    }
    case RuntimeProfile::ForwardRuntime:
        g.build_allowed = true;
        g.headline = info.name + " — targets this host's runtime forward";
        g.detail = "The package targets the build host's runtime and newer "
                   "hosts. It is not guaranteed on hosts older than this one and "
                   "makes no Core Portable claim.";
        g.notes.push_back("Not verified against the Tux32 Core 1 ceiling — pick "
                          "Core Portable for the widest reach.");
        break;
    case RuntimeProfile::NativeCapture:
        g.build_allowed = true;
        g.headline = info.name + " — host-locked (not portable)";
        g.detail = "The package captures this host's environment and targets "
                   "matching hosts only. It makes no portability claim.";
        g.notes.push_back(
            "Native Capture is not cross-distribution portable by design.");
        break;
    }
    return g;
}

// --------------------------------------------------- first-run welcome (DX8)

/// A non-blocking warning about a version string, or "" when it is unremarkable.
///
/// FORMAT-0.1 §8 orders ANY pair of strings — non-numeric components compare as
/// byte strings — so no version is invalid and the Builder must not reject one.
/// But updates require the new version to be strictly GREATER under that order,
/// and a version whose first component is not a number sorts after every
/// numeric one, so "release-2" can never be superseded by "3". That is worth
/// saying before a package ships, not after the first update is refused.
inline std::string version_advisory(const std::string& version) {
    if (version.empty()) return "";
    const std::size_t dot = version.find('.');
    const std::string first = version.substr(0, dot);
    const bool numeric =
        !first.empty() && std::all_of(first.begin(), first.end(), [](char c) {
            return c >= '0' && c <= '9';
        });
    if (!numeric) {
        return "Version \"" + version +
               "\" does not start with a number. FORMAT-0.1 §8 sorts "
               "non-numeric components after numeric ones, so a later numeric "
               "version can never supersede this one and updates to it will be "
               "refused as downgrades.";
    }
    if (version.find(' ') != std::string::npos) {
        return "Version \"" + version +
               "\" contains a space. It is legal, but it orders as text and "
               "reads badly everywhere it is shown.";
    }
    return "";
}

/// Whether `relative` inside `folder` could plausibly START an application: an
/// ELF binary, a script with a shebang, or a file carrying an execute bit.
///
/// The Builder used to pre-select the FIRST candidate alphabetically whenever
/// detection found no runnable executable, so pointing it at a folder of plain
/// files happily produced a signed package whose entrypoint was `data.txt` —
/// reported as "Build succeeded" and "Verification: PASSED", because a package
/// verifies against its own hashes regardless of whether its entrypoint can
/// run. Nothing downstream catches this: the failure surfaces only when a user
/// installs the package and tries to launch it.
inline bool entrypoint_looks_runnable(const std::filesystem::path& folder,
                                      const std::string& relative) {
    if (relative.empty()) return false;
    const std::filesystem::path file = folder / relative;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(file, ec)) return false;

#ifndef _WIN32
    // POSIX only. Windows has no execute bit, and std::filesystem reports one
    // for every ordinary file there — which would make a .txt "runnable".
    const std::filesystem::perms p =
        std::filesystem::status(file, ec).permissions();
    if (!ec && (p & (std::filesystem::perms::owner_exec |
                     std::filesystem::perms::group_exec |
                     std::filesystem::perms::others_exec)) !=
                   std::filesystem::perms::none) {
        return true;
    }
#endif

    // No execute bit (a fresh copy or a FAT/NTFS mount often loses it): accept
    // anything whose first bytes say it is a program.
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;
    char magic[4] = {0, 0, 0, 0};
    in.read(magic, 4);
    const std::streamsize got = in.gcount();
    if (got >= 4 && magic[0] == '\x7f' && magic[1] == 'E' && magic[2] == 'L' &&
        magic[3] == 'F') {
        return true;
    }
    return got >= 2 && magic[0] == '#' && magic[1] == '!';
}

/// Whether "Generate a new signing key" must REUSE the key already at `path`
/// rather than writing a new one over it.
///
/// It must, whenever the file exists. A signing key is the durable identity of
/// every application signed with it, and this runtime has no authenticated key
/// rotation — replacing the file permanently ends the ability to ship an update
/// for that App ID, and the installed copy would refuse the next package as
/// "signed by a different key". The Builder's default path is
/// ~/<app-id>.key.json, so the SECOND build of the same application lands
/// exactly on the first build's key. `lexe build` already reuses a project's
/// existing key.json; this is the same rule.
inline bool should_reuse_existing_key(const std::filesystem::path& path) {
    if (path.empty()) return false;
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec);
}

/// The marker whose presence means "the welcome screen has been dismissed".
inline std::filesystem::path welcome_marker(const Paths& paths) {
    return paths.home() / "builder-welcome-seen";
}

/// Show the welcome screen only until the user has dismissed it once.
inline bool should_show_welcome(const Paths& paths) {
    std::error_code ec;
    return !std::filesystem::is_regular_file(welcome_marker(paths), ec);
}

/// Record that the welcome screen has been seen (best-effort).
inline void mark_welcome_seen(const Paths& paths) {
    const std::filesystem::path marker = welcome_marker(paths);
    std::error_code ec;
    std::filesystem::create_directories(marker.parent_path(), ec);
    try {
        util::spit(marker, std::string_view("1\n"));
    } catch (const std::exception&) {
        // Best-effort: the welcome screen simply shows again next time.
    }
}

/// The welcome copy (plain text; the GTK layer styles it). Kept here so it is
/// unit-testable and so the wording stays consistent with the docs.
inline std::string welcome_body() {
    return
        "Lexe Builder turns a folder of compiled files into a single signed "
        ".lexe package that anyone can install with one click.\n\n"
        "How it works\n"
        "  1. Point the builder at your application's folder.\n"
        "  2. It detects the executable, architecture, icons and dependencies.\n"
        "  3. You confirm the metadata, permissions and runtime profile.\n"
        "  4. It signs and verifies the package for you.\n\n"
        "Core Portable packages are checked against the Tux32 Core 1 contract, "
        "so a package that verifies here runs unchanged on any conforming host.\n\n"
        "Learn more in docs/TUTORIAL.md and docs/SDK.md.";
}

// ------------------------------------------------------- build progress (DX1)

/// The ordered, human-readable build stages shown on the progress screen —
/// meaningful steps, never raw compiler/packer logs.
inline const std::vector<std::string>& build_stages() {
    static const std::vector<std::string> kStages = {
        "Analyzing", "Collecting", "Packaging",
        "Signing",   "Verifying",  "Finalizing"};
    return kStages;
}

// ------------------------------------------------- plain-language explanations

/// A plain-language explanation of the selected Runtime Profile — its name,
/// portability, and what it means — updated live as the developer chooses. Core
/// Portable adds the Tux32 Core 1 note so the guarantee is explained in place.
inline std::string profile_explanation_text(RuntimeProfile p) {
    const RuntimeProfileInfo& i = runtime_profile_info(p);
    std::string s = i.name + " — " + i.portability + " portability.\n" +
                    i.description;
    if (p == RuntimeProfile::CorePortable) {
        s += "\n\nVerified against the Tux32 Core 1 contract (a dynamically "
             "linked x86-64 ELF within the glibc 2.31 symbol ceiling): a package "
             "that passes runs unchanged on any conforming host. The Build step "
             "will not let a non-conforming package claim this profile.";
    }
    return s;
}

/// One sentence on what packaging verifies before the result is shown — the
/// "Verifying" stage, in plain words.
inline std::string verification_note() {
    return "Every packaged file is hashed and the whole package is signed with "
           "your key, then re-verified end to end before you see the result — "
           "the same checks a user's runtime runs on install.";
}

// -------------------------------------------------------------- theme (DX5)

/// The theme choices the toggle offers, in display order, as the values they
/// persist.
///
/// These are exactly the values `Settings::set("theme", …)` accepts, because
/// the GUI toggle and `lexe config set theme` are ONE setting. A second store
/// — a GTK setting, a dotfile of our own — would let the two disagree about
/// what the user chose, and whichever wrote last would silently win.
inline const std::vector<std::string>& theme_choices() {
    static const std::vector<std::string> kChoices = {"system", "light", "dark"};
    return kChoices;
}

/// The human label for a theme value.
///
/// "Follow system" rather than "System", matching the Installer word for word:
/// the two GUIs drive ONE persisted setting, and naming it differently in each
/// invites the reader to wonder whether they are two. "System" also reads as a
/// third palette alongside Light and Dark rather than as deferring to the
/// desktop, which is what it actually does.
inline std::string theme_label(const std::string& value) {
    if (value == "light") return "Light";
    if (value == "dark") return "Dark";
    return "Follow system";
}

/// The toggle position for a persisted theme value.
///
/// An unknown value (a hand-edited settings file, or one written by a newer
/// build) selects System rather than leaving the toggle blank — the same
/// fallback style::theme_from_string makes, mirrored here so the widget and
/// the stylesheet can never disagree about which theme is in force.
inline int theme_choice_index(const std::string& value) {
    const std::vector<std::string>& choices = theme_choices();
    for (std::size_t i = 0; i < choices.size(); ++i) {
        if (choices[i] == value) return static_cast<int>(i);
    }
    return 0; // "system"
}

/// The theme value at toggle position `index` (out of range -> "system").
inline std::string theme_choice_at(int index) {
    const std::vector<std::string>& choices = theme_choices();
    if (index < 0 || static_cast<std::size_t>(index) >= choices.size()) {
        return choices[0];
    }
    return choices[static_cast<std::size_t>(index)];
}

/// The persisted theme, or "system" when the settings file cannot be read.
///
/// A corrupt settings file must not stop the Builder from opening — the window
/// falls back to following the desktop and every build still works. `lexe
/// config reset` is the repair, and the CLI is where it is explained.
inline std::string load_theme(const Paths& paths) {
    try {
        return Settings::load(paths).theme;
    } catch (const std::exception&) {
        return "system";
    }
}

/// Persist `value` as the theme. Returns "" on success, or the reason it could
/// not be saved.
///
/// Settings are RE-READ here rather than carried over from startup: `lexe
/// config set` may have written the file while this window was open, and
/// saving a snapshot taken at launch would quietly roll those other
/// preferences back to whatever they were then.
inline std::string persist_theme(const Paths& paths, const std::string& value) {
    try {
        Settings settings = Settings::load(paths);
        settings.set("theme", value); // validates; throws on an unknown value
        settings.save(paths);
    } catch (const std::exception& e) {
        return e.what();
    }
    return std::string();
}

// ------------------------------------------------------- drag and drop (DX1)

/// What a drop onto the Builder window means for the Source step.
struct DropDecision {
    bool accepted = false;
    std::string folder;  // the source folder, when accepted
    std::string message; // what to tell the user; never empty
};

/// Decide what a drop of `paths` — the dropped text/uri-list already resolved
/// to LOCAL filesystem paths — should do.
///
/// Everything except the URI decoding lives here so the rules are testable
/// without a display. The three refusals are all mistakes people actually
/// make: dropping the executable instead of the folder that holds it, dropping
/// a remote/virtual location that has no local path at all, and dropping a
/// multiple selection — where silently taking the first item would package
/// something the developer never pointed at.
inline DropDecision decide_drop(const std::vector<std::filesystem::path>& paths) {
    DropDecision d;
    if (paths.empty()) {
        d.message = "Nothing that lives on this machine was dropped. Drag the "
                    "folder that holds your compiled application out of a file "
                    "manager.";
        return d;
    }
    if (paths.size() > 1) {
        d.message = "Several items were dropped. Drop one folder — the one "
                    "that holds your compiled application.";
        return d;
    }
    const std::filesystem::path& p = paths.front();
    std::error_code ec;
    if (std::filesystem::is_directory(p, ec)) {
        d.accepted = true;
        d.folder = p.string();
        d.message = "Dropped folder: " + d.folder;
        return d;
    }
    if (std::filesystem::is_regular_file(p, ec)) {
        d.message = "\"" + p.filename().string() +
                    "\" — that is a file; drop the folder that holds your "
                    "compiled application.";
        return d;
    }
    d.message = "\"" + p.string() +
                "\" is not a folder this build can read. Drop the folder that "
                "holds your compiled application.";
    return d;
}

} // namespace lexe::gui
// ===========================================================================
// GTK 3 wizard (Phase 2 / DX1). A seven-step "Publish"-style flow: Source →
// Dependencies → Architecture → Installer → Signing → Output → Build, then a
// build-report result screen. Compiled only when <gtk/gtk.h> is available — the
// Linux-only `lexe-builder` target. All decision/formatting logic lives in the
// GTK-free lexe::gui view model above; this layer is presentation + wiring.
// ===========================================================================
#ifndef LEXE_GUI_VIEWMODEL_ONLY

#include "core/buildreport.hpp"
#include "core/crypto.hpp"
#include "core/depengine.hpp"
#include "core/error.hpp"
#include "core/manifest.hpp"
#include "core/package.hpp"
#include "core/runtime_profile.hpp"
#include "core/trust.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"

#include <gtk/gtk.h>

#include <exception>

namespace {

/// The shared visual language (src/gui/style.hpp) — see the installer for the
/// same alias; this GTK layer is outside lexe::gui.
namespace style = lexe::gui::style;

namespace fs = std::filesystem;

/// A file/folder picker that says where it points.
///
/// The control this replaces, GtkFileChooserButton, renders as a narrow combo
/// showing the chosen item's BASENAME and nothing else: two different folders
/// both called `build` are indistinguishable in it, and there is no way to
/// tell whether the tree about to be packaged and signed is the one you meant.
/// This is a labelled button plus the FULL path underneath it, and an explicit
/// empty state instead of a combo that merely looks unfilled.
struct PathPicker {
    GtkWidget* root = nullptr;      // the card; sensitivity is set on this
    GtkWidget* button = nullptr;
    GtkWidget* path_label = nullptr;
    std::string path;               // "" until something is chosen
    std::string empty_text;
};

/// Whole-application state, owned by main(). Widget pointers are touched on the
/// GTK main thread only; the plain-data fields captured on Build are read by one
/// worker thread and read back on the main thread after its final g_idle_add.
struct BuilderState {
    GtkWidget* window = nullptr;
    GtkWidget* stack = nullptr;        // named pages: step0..6 + progress + result
    GtkWidget* step_title = nullptr;
    GtkWidget* step_subtitle = nullptr;
    GtkWidget* step_counter = nullptr;
    GtkWidget* back_button = nullptr;
    GtkWidget* next_button = nullptr;
    GtkWidget* banner_label = nullptr;

    // Theme (DX5). Persisted as the `theme` setting — the SAME one `lexe
    // config set theme` writes; see lexe::gui::persist_theme.
    GtkWidget* theme_combo = nullptr;
    std::string theme = "system";
    /// The desktop's OWN dark preference, snapshotted in main() before the
    /// first style::apply() overwrote it. See apply_theme().
    gboolean desktop_prefers_dark = FALSE;
    /// The banner currently on screen, replayed when the theme flips: its
    /// colours are baked into Pango markup rather than coming from the
    /// stylesheet, so it cannot restyle itself.
    std::string banner_text;
    bool banner_ok = true;

    // First-run welcome (DX8).
    GtkWidget* welcome_dont_show = nullptr;
    bool welcome_visible = false;

    // Step 1 — Source.
    PathPicker source_picker;
    GtkWidget* source_summary = nullptr;
    // Step 2 — Dependencies.
    GtkWidget* deps_box = nullptr;
    // Step 3 — Architecture.
    GtkWidget* arch_x86_check = nullptr;
    GtkWidget* arch_arm_check = nullptr;
    // Step 4 — Installer metadata.
    GtkWidget* id_entry = nullptr;
    GtkWidget* name_entry = nullptr;
    GtkWidget* version_entry = nullptr;
    GtkWidget* entrypoint_combo = nullptr;
    GtkWidget* publisher_entry = nullptr;
    GtkWidget* website_entry = nullptr;
    GtkWidget* description_entry = nullptr;
    GtkWidget* categories_entry = nullptr;
    GtkWidget* icon_note = nullptr;
    GtkWidget* perm_network_check = nullptr;
    GtkWidget* perm_userfiles_check = nullptr;
    // Step 5 — Signing.
    GtkWidget* key_generate_radio = nullptr;
    GtkWidget* key_existing_radio = nullptr;
    GtkWidget* generated_key_entry = nullptr;
    PathPicker existing_key_picker;
    // Step 6 — Output.
    GtkWidget* output_entry = nullptr;
    GtkWidget* profile_combo = nullptr;
    GtkWidget* profile_explanation = nullptr; // updates as the profile changes
    // Step 7 — Build summary + progress.
    GtkWidget* step_header = nullptr;   // the lit step strip (hidden on welcome)
    GtkWidget* footer = nullptr;        // the action bar (hidden on welcome)
    GtkWidget* build_summary = nullptr;
    GtkWidget* spinner = nullptr;
    GtkWidget* progress_label = nullptr;
    // Result page.
    GtkWidget* result_heading = nullptr;
    GtkWidget* result_report = nullptr;

    int step = 0; // index into lexe::gui::wizard_steps()

    // Data (main thread).
    std::string folder;
    lexe::gui::SourceDetection detection;
    bool detection_done = false;
    /// A detection worker is running. Nothing else may start a second one —
    /// two workers would write st->detection concurrently. begin_detection
    /// disables Next/Back for this reason; the drop target is not covered by
    /// that, so it consults this flag instead.
    bool detecting = false;
    std::string detection_error; // worker -> main loop; "" on success

    // Captured on Build (main thread) → worker.
    lexe::gui::BuilderForm form;
    bool generate_key = true;
    /// Set when "Generate a new signing key" found a key already at that path
    /// and reused it instead of destroying it. Reported on the result screen so
    /// the developer knows which key signed the package.
    bool reused_existing_key = false;
    std::string existing_key_path;
    std::string generated_key_path;
    std::string output_path;

    // Results (worker → main).
    /// A build worker is running. The build MOVES st->detection into the
    /// build report, so a detection worker started meanwhile would be writing
    /// the very object the build is reading. The Build page disables
    /// Next/Back; the drop target is not a button, so it consults this.
    bool building = false;

    bool build_ok = false;
    std::string build_error;
    std::string built_checksum;
    lexe::BuildReport report;
};

std::string trim(const std::string& text) {
    const std::size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return std::string();
    const std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

std::string entry_text(GtkWidget* entry) {
    const gchar* text = gtk_entry_get_text(GTK_ENTRY(entry));
    return trim(text != nullptr ? std::string(text) : std::string());
}

/// The severity text colours style.hpp renders in, resolved for the theme now
/// in force.
///
/// A handful of labels here are built as Pango markup, so their colour is
/// baked into the label instead of coming from the stylesheet — and the
/// light-theme green and near-black these used to hardcode are unreadable on
/// the dark canvas the theme toggle can now select (a failed-build banner that
/// cannot be read is worse than no banner). The values are the ones style.hpp
/// already defines for `.lexe-banner.ok/.caution/.danger` and for body text in
/// each palette, so a message reads the same whether it is drawn as a styled
/// callout or as markup. A `lexe-ok` / `lexe-caution` TEXT class in style.hpp
/// would retire this helper — style.hpp is a frozen contract here, so this
/// mirrors it rather than extending it.
struct SeverityColours {
    const char* ok;
    const char* caution;
    const char* text;
    const char* danger;
};

SeverityColours severity_colours(const BuilderState* st) {
    return style::resolve_dark(style::theme_from_string(st->theme))
               ? SeverityColours{"#6ee7a8", "#fbbf5c", "#e7eaf0", "#ff8f8a"}
               : SeverityColours{"#15803d", "#b45309", "#0f172a", "#b91c1c"};
}

void set_banner(BuilderState* st, bool ok, const std::string& text) {
    // Remembered so a theme flip can redraw it in the other palette's colours.
    st->banner_text = text;
    st->banner_ok = ok;
    // The banner lives in the footer, and the welcome screen hides the footer —
    // so every refusal raised from that screen was written to a hidden widget
    // and the window did not change at all. A drop refused on the first screen
    // anyone sees was therefore completely silent. Reveal the footer for as
    // long as there is something to say, and take it away again when there is
    // not; Back/Next stay hidden independently, so this shows the message
    // without bringing back wizard chrome the welcome screen has no use for.
    if (st->footer != nullptr && st->welcome_visible) {
        if (text.empty()) {
            gtk_widget_hide(st->footer);
        } else {
            gtk_widget_show(st->footer);
        }
    }
    if (text.empty()) {
        gtk_label_set_text(GTK_LABEL(st->banner_label), "");
        return;
    }
    const SeverityColours colours = severity_colours(st);
    gchar* escaped = g_markup_escape_text(text.c_str(), -1);
    gchar* markup = g_strdup_printf(
        "<span weight=\"bold\" foreground=\"%s\">%s</span>",
        ok ? colours.ok : colours.danger, escaped);
    gtk_label_set_markup(GTK_LABEL(st->banner_label), markup);
    g_free(markup);
    g_free(escaped);
}

/// Reveal the wizard chrome that the welcome screen hides.
///
/// Shared by the "Get started" button and by a folder dropped ONTO the welcome
/// screen: a drop has to be able to leave the welcome screen too, or detection
/// would run behind a page that has no Back/Next on it.
void leave_welcome(BuilderState* st) {
    if (!st->welcome_visible) return;
    st->welcome_visible = false;
    gtk_widget_show(st->back_button);
    gtk_widget_show(st->next_button);
    if (st->step_header != nullptr) gtk_widget_show(st->step_header);
    if (st->footer != nullptr) gtk_widget_show(st->footer);
}

// --- small widget helpers ---------------------------------------------------

GtkWidget* section_heading(const char* text) {
    GtkWidget* label = gtk_label_new(nullptr);
    style::add_class(label, "lexe-section-heading");
    // Escape the heading: a "&" or "<" would otherwise break Pango markup and
    // render the heading blank (see the installer's add_section for the same fix).
    gchar* escaped = g_markup_escape_text(text, -1);
    gchar* markup = g_strdup_printf("<b>%s</b>", escaped);
    gtk_label_set_markup(GTK_LABEL(label), markup);
    g_free(markup);
    g_free(escaped);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    return label;
}

GtkWidget* body_label(const char* text) {
    GtkWidget* label = gtk_label_new(text);
    style::add_class(label, "lexe-body");
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    return label;
}

/// A label + entry row appended to a grid at `row`; returns the entry.
GtkWidget* grid_entry(GtkWidget* grid, int row, const char* label,
                      const char* placeholder) {
    GtkWidget* lab = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(lab), 0.0f);
    gtk_grid_attach(GTK_GRID(grid), lab, 0, row, 1, 1);
    GtkWidget* entry = gtk_entry_new();
    if (placeholder != nullptr) {
        gtk_entry_set_placeholder_text(GTK_ENTRY(entry), placeholder);
    }
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), entry, 1, row, 1, 1);
    return entry;
}

GtkWidget* page_scroller(GtkWidget* child) {
    GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroller), child);
    return scroller;
}

// --- path pickers -----------------------------------------------------------

/// Draw `picker`'s current path, or its empty state.
///
/// The path gets `lexe-mono` so a path is read as a path — the one place in
/// this window where character-level accuracy matters — and the empty state
/// gets `lexe-muted`, so "nothing chosen yet" is visibly not a value.
void path_picker_render(PathPicker* picker) {
    if (picker->path.empty()) {
        style::remove_class(picker->path_label, "lexe-mono");
        style::remove_class(picker->path_label, "lexe-body");
        style::add_class(picker->path_label, "lexe-muted");
        gtk_label_set_text(GTK_LABEL(picker->path_label),
                           picker->empty_text.c_str());
        gtk_widget_set_tooltip_text(picker->path_label, nullptr);
        return;
    }
    style::remove_class(picker->path_label, "lexe-muted");
    style::add_class(picker->path_label, "lexe-body");
    style::add_class(picker->path_label, "lexe-mono");
    gtk_label_set_text(GTK_LABEL(picker->path_label), picker->path.c_str());
    gtk_widget_set_tooltip_text(picker->path_label, picker->path.c_str());
}

void path_picker_set(PathPicker* picker, const std::string& path) {
    picker->path = path;
    path_picker_render(picker);
}

/// Build a picker card: heading, action button, and the chosen path below it.
/// The caller connects the button and packs the returned card.
GtkWidget* path_picker_build(PathPicker* picker, const char* heading,
                             const char* button_label, const char* empty_text) {
    picker->empty_text = empty_text;
    GtkWidget* card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    style::add_class(card, "lexe-card");
    picker->root = card;
    gtk_box_pack_start(GTK_BOX(card), section_heading(heading), FALSE, FALSE, 0);

    picker->button = gtk_button_new_with_label(button_label);
    style::add_class(picker->button, "lexe-primary");
    // Left-aligned and sized to its label: packed plain into a vertical box a
    // GTK button stretches the full width of the card, which reads as a banner
    // rather than as something to press.
    gtk_widget_set_halign(picker->button, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(card), picker->button, FALSE, FALSE, 0);

    picker->path_label = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(picker->path_label), 0.0f);
    // Selectable so a path can be copied out; GTK's select-on-focus is turned
    // off in main(), so it does not come up pre-highlighted.
    gtk_label_set_selectable(GTK_LABEL(picker->path_label), TRUE);
    // Wrapped, never ellipsized: a truncated path is the exact failure this
    // control exists to end, and a project deep in a home directory is
    // routinely wider than the window. WORD_CHAR can break the single long
    // slash-separated token that a path is.
    gtk_label_set_line_wrap(GTK_LABEL(picker->path_label), TRUE);
    gtk_label_set_line_wrap_mode(GTK_LABEL(picker->path_label),
                                 PANGO_WRAP_WORD_CHAR);
    gtk_label_set_max_width_chars(GTK_LABEL(picker->path_label), 64);
    gtk_box_pack_start(GTK_BOX(card), picker->path_label, FALSE, FALSE, 0);

    path_picker_render(picker);
    return card;
}

/// Open a chooser and return the chosen path, or "" if it was cancelled.
///
/// GtkFileChooserNative hands the job to the desktop's OWN chooser through the
/// portal where there is one — the dialog the user already knows, with their
/// bookmarks and recent places in it, and the only chooser that can reach
/// files a sandboxed app otherwise cannot see. Where no portal exists it falls
/// back to GTK's in-process dialog, so this is never worse than the control it
/// replaces.
std::string run_chooser(BuilderState* st, const char* title,
                        GtkFileChooserAction action, const char* accept,
                        const std::string& start_at, bool key_filters) {
    GtkFileChooserNative* native = gtk_file_chooser_native_new(
        title, GTK_WINDOW(st->window), action, accept, "Cancel");
    GtkFileChooser* chooser = GTK_FILE_CHOOSER(native);
    // Re-open where the last choice was made rather than at $HOME: choosing a
    // folder, looking at it, and choosing again is the common case.
    if (!start_at.empty()) {
        gtk_file_chooser_set_filename(chooser, start_at.c_str());
    }
    if (key_filters) {
        GtkFileFilter* keys = gtk_file_filter_new();
        gtk_file_filter_set_name(keys, "Signing keys (*.json)");
        gtk_file_filter_add_pattern(keys, "*.json");
        gtk_file_chooser_add_filter(chooser, keys);
        // A second, unfiltered entry: a key file that is not named *.json is
        // still a key file, and a filter with no way out hides it completely.
        GtkFileFilter* all = gtk_file_filter_new();
        gtk_file_filter_set_name(all, "All files");
        gtk_file_filter_add_pattern(all, "*");
        gtk_file_chooser_add_filter(chooser, all);
    }
    std::string chosen;
    if (gtk_native_dialog_run(GTK_NATIVE_DIALOG(native)) ==
        GTK_RESPONSE_ACCEPT) {
        gchar* path = gtk_file_chooser_get_filename(chooser);
        if (path != nullptr) {
            chosen = path;
            g_free(path);
        }
    }
    g_object_unref(native);
    return chosen;
}

void on_choose_source_folder(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    const std::string chosen =
        run_chooser(st, "Choose your application's folder",
                    GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, "Use this folder",
                    st->folder, /*key_filters=*/false);
    // A cancelled chooser keeps whatever was chosen before. Clearing it would
    // throw away a valid selection because the user changed their mind about
    // changing it.
    if (chosen.empty()) return;
    st->folder = chosen;
    path_picker_set(&st->source_picker, chosen);
    set_banner(st, true, "");
}

void on_choose_key_file(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    const std::string chosen = run_chooser(
        st, "Choose your signing key", GTK_FILE_CHOOSER_ACTION_OPEN,
        "Use this key", st->existing_key_picker.path, /*key_filters=*/true);
    if (chosen.empty()) return;
    path_picker_set(&st->existing_key_picker, chosen);
}

// --- form gathering ---------------------------------------------------------

lexe::RuntimeProfile selected_profile(BuilderState* st) {
    switch (gtk_combo_box_get_active(GTK_COMBO_BOX(st->profile_combo))) {
    case 1: return lexe::RuntimeProfile::ForwardRuntime;
    case 2: return lexe::RuntimeProfile::NativeCapture;
    default: return lexe::RuntimeProfile::CorePortable;
    }
}

// Keep the profile explanation in sync with the chosen profile (WS2).
void on_profile_changed(GtkComboBox*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    if (st->profile_explanation != nullptr) {
        gtk_label_set_text(
            GTK_LABEL(st->profile_explanation),
            lexe::gui::profile_explanation_text(selected_profile(st)).c_str());
    }
}

std::vector<std::string> split_commas(const std::string& text) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t comma = text.find(',', start);
        const std::string part =
            trim(text.substr(start, comma == std::string::npos
                                        ? std::string::npos
                                        : comma - start));
        if (!part.empty()) out.push_back(part);
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return out;
}

std::string resolve_output_path(BuilderState* st, const std::string& app_id) {
    const std::string text = entry_text(st->output_entry);
    if (!text.empty()) return text;
    const gchar* home = g_get_home_dir();
    const std::string base = app_id.empty() ? std::string("app") : app_id;
    return (fs::path(home != nullptr ? home : ".") / (base + ".lexe")).string();
}

lexe::gui::BuilderForm gather_form(BuilderState* st) {
    lexe::gui::BuilderForm form;
    form.app_id = entry_text(st->id_entry);
    form.name = entry_text(st->name_entry);
    form.version = entry_text(st->version_entry);
    form.publisher_name = entry_text(st->publisher_entry);
    form.publisher_website = entry_text(st->website_entry);
    form.description = entry_text(st->description_entry);
    form.categories = split_commas(entry_text(st->categories_entry));
    gchar* entrypoint =
        gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(st->entrypoint_combo));
    form.entrypoint = entrypoint != nullptr ? std::string(entrypoint) : std::string();
    if (entrypoint != nullptr) g_free(entrypoint);
    form.arch_x86_64 =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->arch_x86_check));
    form.arch_aarch64 =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->arch_arm_check));
    form.perm_network =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->perm_network_check));
    form.perm_user_files_selected =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->perm_userfiles_check));
    form.available_entrypoints = st->detection.entrypoints;
    form.profile = selected_profile(st);
    form.payload_size_bytes = st->detection.payload_size;
    form.bundle_icons = !st->detection.icons.empty();
    return form;
}

// --- source detection + prefill ---------------------------------------------

void render_dependencies(BuilderState* st) {
    // Clear the container.
    GList* children = gtk_container_get_children(GTK_CONTAINER(st->deps_box));
    for (GList* c = children; c != nullptr; c = c->next) {
        gtk_widget_destroy(GTK_WIDGET(c->data));
    }
    g_list_free(children);

    const std::vector<lexe::gui::DependencyRow> rows =
        lexe::gui::dependency_rows(st->detection.dependencies);
    if (rows.empty()) {
        // Two very different situations produced the same sentence. An empty
        // list because nothing was ANALYZED is not evidence of a static or
        // script app — it means the folder had no runnable executable to read,
        // which is a problem the developer needs to hear about, not a clean
        // bill of health.
        gtk_box_pack_start(
            GTK_BOX(st->deps_box),
            body_label(st->detection.ok
                           ? "No shared-library dependencies — this executable "
                             "is statically linked, or it is a script."
                           : "Nothing was analyzed: no runnable executable was "
                             "found in this folder, so its dependencies are "
                             "unknown. Choose a folder containing your compiled "
                             "application."),
            FALSE, FALSE, 0);
    }
    for (const lexe::gui::DependencyRow& row : rows) {
        GtkWidget* frame = gtk_frame_new(nullptr);
        GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        gtk_container_set_border_width(GTK_CONTAINER(box), 6);
        const std::string title = row.soname + "  —  " + row.handling;
        GtkWidget* head = gtk_label_new(nullptr);
        gchar* esc = g_markup_escape_text(title.c_str(), -1);
        // Both colours follow the theme. The near-black this used to
        // hardcode for the ordinary case put every dependency name at
        // roughly the background's own brightness once the window went
        // dark — the whole list unreadable, on the one screen whose
        // entire job is to be read.
        const SeverityColours colours = severity_colours(st);
        gchar* markup = g_strdup_printf(
            "<span weight=\"bold\" foreground=\"%s\">%s</span>",
            row.warn ? colours.caution : colours.text, esc);
        gtk_label_set_markup(GTK_LABEL(head), markup);
        g_free(markup);
        g_free(esc);
        gtk_label_set_xalign(GTK_LABEL(head), 0.0f);
        gtk_box_pack_start(GTK_BOX(box), head, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), body_label(row.reason.c_str()), FALSE,
                           FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box),
                           body_label(("→ " + row.recommendation).c_str()),
                           FALSE, FALSE, 0);
        gtk_container_add(GTK_CONTAINER(frame), box);
        gtk_box_pack_start(GTK_BOX(st->deps_box), frame, FALSE, FALSE, 0);
    }
    gtk_widget_show_all(st->deps_box);
}

gboolean on_detection_finished(gpointer user_data);
void update_step(BuilderState* st); // defined with the navigation below

/// The persisted theme, or "system" when even the paths cannot be resolved.
std::string startup_theme() {
    try {
        return lexe::gui::load_theme(lexe::Paths::detect());
    } catch (const std::exception&) {
        return "system";
    }
}

/// Persist the theme; "" on success, otherwise the reason it failed.
std::string persist_theme_now(const std::string& value) {
    try {
        return lexe::gui::persist_theme(lexe::Paths::detect(), value);
    } catch (const std::exception& e) {
        return e.what();
    }
}

/// Restyle the LIVE window to `value` — no restart, no reopened window.
void apply_theme(BuilderState* st, const std::string& value) {
    st->theme = value;
    // style::apply() writes the theme it resolved into GTK's
    // gtk-application-prefer-dark-theme, and resolve_dark(System) reads that
    // same flag back to ask what the desktop wants. So once a window has been
    // Dark, the flag says "dark" from then on, and Dark -> System would stay
    // dark on a light desktop. Put the desktop's own answer back first; it was
    // snapshotted in main() before the first apply() could overwrite it.
    if (value == "system") {
        if (GtkSettings* settings = gtk_settings_get_default()) {
            g_object_set(settings, "gtk-application-prefer-dark-theme",
                         st->desktop_prefers_dark, nullptr);
        }
    }
    style::apply(style::theme_from_string(value));
    // The two surfaces whose colours are Pango markup rather than stylesheet
    // rules cannot restyle themselves, so redraw them by hand.
    render_dependencies(st);
    if (!st->banner_text.empty()) set_banner(st, st->banner_ok, st->banner_text);
}

void on_theme_changed(GtkComboBox* combo, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    const std::string value = lexe::gui::theme_choice_at(
        gtk_combo_box_get_active(GTK_COMBO_BOX(combo)));
    if (value == st->theme) return; // includes the programmatic initial select
    apply_theme(st, value);
    // The window is already restyled; a settings file that cannot be written
    // costs the user the choice next launch, not this one, so say so and carry
    // on rather than reverting what they can plainly see happened.
    const std::string error = persist_theme_now(value);
    if (!error.empty()) {
        set_banner(st, false,
                   "The theme changed for this window, but could not be saved: " +
                       error);
    }
}

/// Detection walks the whole source folder, reads every ELF and resolves the
/// full dependency graph. That ran on the UI THREAD, so choosing a folder with
/// any real number of files froze the entire wizard — no spinner, no message,
/// no cancel, nothing repainting — for as long as it took. Off the main loop it
/// goes, exactly like the build: the worker touches no GTK, and everything that
/// updates a widget happens back on the main loop via g_idle_add.
gpointer detection_worker(gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    try {
        st->detection = lexe::gui::detect_source(fs::path(st->folder));
        st->detection_error.clear();
    } catch (const std::exception& e) {
        st->detection = {};
        st->detection_error = e.what();
    } catch (...) {
        st->detection = {};
        st->detection_error = "unknown error while inspecting the folder";
    }
    g_idle_add(on_detection_finished, st);
    return nullptr;
}

/// Start detection and tell the user it is running. Next/Back stay disabled
/// until it finishes, so the step cannot advance on a half-built detection and
/// a second click cannot start a second worker.
void begin_detection(BuilderState* st) {
    st->detecting = true;
    gtk_widget_set_sensitive(st->next_button, FALSE);
    gtk_widget_set_sensitive(st->back_button, FALSE);
    gtk_label_set_text(
        GTK_LABEL(st->source_summary),
        ("Inspecting " + st->folder +
         " — reading the executable and resolving its dependencies. This can "
         "take a moment for a large folder.")
            .c_str());
    g_thread_unref(g_thread_new("lexe-detect", detection_worker, st));
}

/// Apply a COMPLETED detection to the wizard. Main thread only.
void apply_detection(BuilderState* st) {
    st->detection_done = true;

    gtk_label_set_text(GTK_LABEL(st->source_summary),
                       st->detection.summary.c_str());

    // Entrypoint combo.
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(st->entrypoint_combo));
    for (const std::string& f : st->detection.entrypoints) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st->entrypoint_combo),
                                       f.c_str());
    }
    int active = 0;
    for (std::size_t i = 0; i < st->detection.entrypoints.size(); ++i) {
        if (st->detection.entrypoints[i] == st->detection.main_executable) {
            active = static_cast<int>(i);
            break;
        }
    }
    // Only pre-select when detection actually FOUND a runnable executable.
    // Defaulting to index 0 otherwise silently nominated the first file
    // alphabetically — a README or a data file — as the thing that starts the
    // application, and the build went through.
    if (!st->detection.entrypoints.empty() &&
        !st->detection.main_executable.empty()) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(st->entrypoint_combo), active);
    }

    // Architecture from detection.
    if (st->detection.detected_arch == "x86_64") {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(st->arch_x86_check), TRUE);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(st->arch_arm_check), FALSE);
    } else if (st->detection.detected_arch == "aarch64") {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(st->arch_x86_check), FALSE);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(st->arch_arm_check), TRUE);
    }

    // A friendly default app name from the folder.
    if (entry_text(st->name_entry).empty() && !st->folder.empty()) {
        gtk_entry_set_text(GTK_ENTRY(st->name_entry),
                           fs::path(st->folder).filename().string().c_str());
    }

    // Icon note.
    if (st->detection.icons.empty()) {
        gtk_label_set_text(GTK_LABEL(st->icon_note),
                           "No icons detected. Add 64.png / 128.png / 256.png / "
                           "scalable.svg (in the folder or an icons/ subfolder) "
                           "for a menu icon.");
    } else {
        std::string found = "Icons detected: ";
        for (std::size_t i = 0; i < st->detection.icons.size(); ++i) {
            found += (i ? ", " : "") + st->detection.icons[i];
        }
        gtk_label_set_text(GTK_LABEL(st->icon_note), found.c_str());
    }

    render_dependencies(st);
}

/// Main-loop continuation of detection_worker: apply the result and advance,
/// or report the failure and stay put.
gboolean on_detection_finished(gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    st->detecting = false;
    gtk_widget_set_sensitive(st->next_button, TRUE);
    gtk_widget_set_sensitive(st->back_button, TRUE);
    if (!st->detection_error.empty()) {
        set_banner(st, false,
                   "Could not inspect that folder: " + st->detection_error);
        gtk_label_set_text(GTK_LABEL(st->source_summary),
                           "Choose a folder, then press Next to detect the "
                           "executable and dependencies.");
        return G_SOURCE_REMOVE;
    }
    apply_detection(st);
    ++st->step;
    update_step(st);
    return G_SOURCE_REMOVE;
}

// --- build summary + worker -------------------------------------------------

void refresh_build_summary(BuilderState* st) {
    st->form = gather_form(st);
    const lexe::gui::ValidationResult v = lexe::gui::validate_form(st->form);
    bool allow = v.ok;
    std::string text;
    if (!v.ok) {
        text = "Please fix before building:\n  " + v.error;
    } else {
        const lexe::RuntimeProfileInfo& p =
            lexe::runtime_profile_info(st->form.profile);
        text = "Ready to build:\n";
        text += "  Application: " + st->form.name + " " + st->form.version +
                " (" + st->form.app_id + ")\n";
        std::string arches;
        for (const std::string& a : lexe::gui::selected_architectures(st->form)) {
            arches += (arches.empty() ? "" : ", ") + a;
        }
        text += "  Architecture(s): " + arches + "\n";
        text += "  Runtime profile: " + p.name + " (" + p.portability + ")\n";
        text += "  Entrypoint: " + st->form.entrypoint + "\n";
        text += "  Signing: " +
                std::string(st->generate_key ? "generate a new key"
                                             : "use an existing key") +
                "\n";
        text += "  Dependencies: " +
                std::to_string(st->detection.dependencies.dependencies.size()) +
                " analyzed\n";

        // Non-blocking: FORMAT-0.1 §8 orders any string, so no version is
        // invalid — but one that can never be superseded is worth saying before
        // the package ships rather than when the first update is refused.
        if (const std::string advisory =
                lexe::gui::version_advisory(st->form.version);
            !advisory.empty()) {
            text += "\n  ! " + advisory + "\n";
        }

        // Profile gate: Core Portable is hard-gated on Tux32 Core 1; other
        // profiles are allowed but labeled. A blocking gate disables Build.
        const lexe::gui::ProfileGate gate = lexe::gui::evaluate_profile_gate(
            st->form.profile, st->detection.dependencies);
        allow = gate.build_allowed;
        text += "\n  " + std::string(gate.blocking ? "\xE2\x9C\x97 " : "\xE2\x80\xA2 ") +
                gate.headline + "\n";
        text += "  " + gate.detail + "\n";
        for (const std::string& n : gate.notes) text += "    ! " + n + "\n";
        if (gate.blocking) {
            text += "\n  Build is disabled: this source does not satisfy the "
                    "Core Portable contract. Fix the items above, or go back and "
                    "choose a "
                    "different runtime profile (the Output step).";
        }
    }
    gtk_label_set_text(GTK_LABEL(st->build_summary), text.c_str());
    gtk_widget_set_sensitive(st->next_button, allow ? TRUE : FALSE);
}

gboolean on_build_finished(gpointer user_data);

/// Worker thread: build, verify, and assemble the build report. NO GTK calls.
gpointer build_worker(gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    std::string tmpdir;
    try {
        lexe::crypto::KeyPair key;
        if (st->generate_key) {
            const fs::path keyfile(st->generated_key_path);
            if (lexe::gui::should_reuse_existing_key(keyfile)) {
                key = lexe::crypto::read_keyfile(keyfile);
                st->reused_existing_key = true;
            } else {
                if (keyfile.has_parent_path()) {
                    std::error_code ec;
                    fs::create_directories(keyfile.parent_path(), ec);
                }
                key = lexe::crypto::generate_keypair();
                lexe::crypto::write_keyfile(keyfile, key);
                st->reused_existing_key = false;
            }
        } else {
            key = lexe::crypto::read_keyfile(fs::path(st->existing_key_path));
        }
        const std::string pubkey = lexe::crypto::encode_public_key(key.public_key);

        const std::string manifest_json =
            lexe::gui::build_manifest_json(st->form, pubkey);
        lexe::Manifest::parse(manifest_json); // throws on §5 violation

        gchar* made = g_dir_make_tmp("lexe-builder-XXXXXX", nullptr);
        if (made == nullptr) {
            throw lexe::Error("could not create a temporary working directory");
        }
        tmpdir = made;
        g_free(made);
        const fs::path manifest_file = fs::path(tmpdir) / "lexe.json";
        lexe::util::spit(manifest_file, std::string_view(manifest_json));

        const fs::path output(st->output_path);
        if (output.has_parent_path()) {
            std::error_code ec;
            fs::create_directories(output.parent_path(), ec);
        }
        lexe::PackageWriter::Inputs inputs;
        inputs.payload_dir = fs::path(st->folder);
        inputs.manifest_file = manifest_file;
        const fs::path icons_dir = fs::path(st->folder) / "icons";
        std::error_code iec;
        if (fs::is_directory(icons_dir, iec)) inputs.icons_dir = icons_dir;
        lexe::PackageWriter::write(inputs, key, output);

        const lexe::VerificationReport report =
            lexe::verify_package(output, /*check_architecture=*/false);
        if (!report.ok()) {
            const lexe::VerificationStage* f = report.first_failure();
            throw lexe::VerificationError(
                f != nullptr ? f->name + ": " + f->detail
                             : std::string("verification failed"));
        }

        // Assemble the build report (DX5): reuse the source analysis.
        lexe::BuildReport r = lexe::assemble_report(
            std::move(st->detection.dependencies), st->form.profile);
        r.app_name = st->form.name;
        r.app_id = st->form.app_id;
        r.app_version = st->form.version;
        r.architectures = lexe::gui::selected_architectures(st->form);
        r.permissions = lexe::gui::selected_permissions(st->form);
        r.signing_fingerprint = lexe::key_fingerprint(key.public_key).grouped;
        r.output_package = output;
        std::error_code sec;
        r.output_size = static_cast<std::uint64_t>(fs::file_size(output, sec));
        r.output_sha256 = lexe::crypto::sha256_file_hex(output);
        st->built_checksum = r.output_sha256;
        st->report = std::move(r);
        st->build_ok = true;
        st->build_error.clear();
    } catch (const std::exception& e) {
        st->build_ok = false;
        st->build_error = e.what();
    } catch (...) {
        st->build_ok = false;
        st->build_error = "unknown build error";
    }
    if (!tmpdir.empty()) {
        std::error_code ec;
        fs::remove_all(fs::path(tmpdir), ec);
    }
    g_idle_add(on_build_finished, st);
    return nullptr;
}

gboolean on_build_finished(gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    st->building = false;
    gtk_spinner_stop(GTK_SPINNER(st->spinner));
    if (!st->build_ok) {
        set_banner(st, false, "Build failed: " + st->build_error);
        gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "step6");
        gtk_widget_set_sensitive(st->next_button, TRUE);
        gtk_widget_set_sensitive(st->back_button, TRUE);
        return G_SOURCE_REMOVE;
    }
    // Plain text plus a style class, NOT a colour baked into Pango markup: the
    // baked colour was resolved once, when the build finished, and a later
    // theme flip restyled the whole window around it — leaving the dark
    // palette's mint green on the light palette's white card at about 1.4:1
    // contrast. A class re-resolves with the stylesheet.
    gtk_label_set_text(GTK_LABEL(st->result_heading), "Build succeeded");
    style::add_class(st->result_heading, "lexe-success");
    // Say WHICH key signed this, and where it lives. The signing key is the
    // application's durable identity and the developer has to keep it; a build
    // that never names the file leaves them with nothing to keep.
    std::string report_text = lexe::render_build_report_text(st->report);
    if (st->generate_key) {
        report_text +=
            st->reused_existing_key
                ? "\nSigning key:   reused the existing key at " +
                      st->generated_key_path +
                      "\n               (a new key would have ended updates for "
                      "this App ID)\n"
                : "\nSigning key:   a NEW key was written to " +
                      st->generated_key_path +
                      "\n               Keep it safe and out of version "
                      "control: it is the identity of every future update.\n";
    }
    gtk_label_set_text(GTK_LABEL(st->result_report), report_text.c_str());
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "result");
    return G_SOURCE_REMOVE;
}

// --- navigation -------------------------------------------------------------

void update_step(BuilderState* st) {
    const auto& steps = lexe::gui::wizard_steps();
    const int n = static_cast<int>(steps.size());
    if (st->step < 0) st->step = 0;
    if (st->step >= n) st->step = n - 1;
    const lexe::gui::WizardStepInfo& info =
        steps[static_cast<std::size_t>(st->step)];

    gchar* page = g_strdup_printf("step%d", st->step);
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), page);
    g_free(page);

    gtk_label_set_text(GTK_LABEL(st->step_title), info.title.c_str());
    gtk_label_set_text(GTK_LABEL(st->step_subtitle), info.subtitle.c_str());
    gchar* counter =
        g_strdup_printf("Step %d of %d", st->step + 1, n);
    gtk_label_set_text(GTK_LABEL(st->step_counter), counter);
    g_free(counter);

    gtk_widget_set_sensitive(st->back_button, st->step > 0 ? TRUE : FALSE);
    const bool last = st->step == n - 1;
    gtk_button_set_label(GTK_BUTTON(st->next_button), last ? "Build" : "Next");
    gtk_widget_set_sensitive(st->next_button, TRUE);
    set_banner(st, true, "");

    if (info.step == lexe::gui::WizardStep::Build) refresh_build_summary(st);
}

void on_back_clicked(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    if (st->step > 0) {
        --st->step;
        update_step(st);
    }
}

void start_build(BuilderState* st) {
    st->form = gather_form(st);
    const lexe::gui::ValidationResult v = lexe::gui::validate_form(st->form);
    if (!v.ok) {
        set_banner(st, false, v.error);
        return;
    }
    // A package whose entrypoint cannot start anything verifies perfectly well
    // against its own hashes — the failure only appears when a user installs it
    // and tries to launch. Catch it here instead.
    if (!lexe::gui::entrypoint_looks_runnable(fs::path(st->folder),
                                              st->form.entrypoint)) {
        set_banner(st, false,
                   "\"" + st->form.entrypoint +
                       "\" does not look like a program: it is not an "
                       "executable, and has no #! line. Choose the file that "
                       "starts your application on the Installer step.");
        return;
    }
    st->generate_key =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->key_generate_radio));
    if (st->generate_key) {
        st->generated_key_path = entry_text(st->generated_key_entry);
        if (st->generated_key_path.empty()) {
            const gchar* home = g_get_home_dir();
            st->generated_key_path =
                (fs::path(home != nullptr ? home : ".") /
                 (st->form.app_id + ".key.json"))
                    .string();
        }
    } else {
        st->existing_key_path = st->existing_key_picker.path;
        if (st->existing_key_path.empty()) {
            set_banner(st, false, "Choose the signing key file, or switch to "
                                  "generating a new key.");
            return;
        }
    }
    st->output_path = resolve_output_path(st, st->form.app_id);

    st->building = true;
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "progress");
    gtk_widget_set_sensitive(st->next_button, FALSE);
    gtk_widget_set_sensitive(st->back_button, FALSE);
    gtk_spinner_start(GTK_SPINNER(st->spinner));
    GThread* thread = g_thread_new("lexe-build", build_worker, st);
    g_thread_unref(thread);
}

void on_next_clicked(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    const auto& steps = lexe::gui::wizard_steps();
    const lexe::gui::WizardStep current =
        steps[static_cast<std::size_t>(st->step)].step;

    if (current == lexe::gui::WizardStep::Source) {
        // st->folder is set the moment a folder is chosen or dropped, so both
        // routes arrive here having already agreed on what is being packaged.
        if (st->folder.empty()) {
            set_banner(st, false,
                       "Choose the folder that holds your application's files, "
                       "or drag it onto this window.");
            return;
        }
        // Detection is asynchronous now; on_detection_finished advances the
        // step when it completes, so do not fall through to ++st->step here.
        begin_detection(st);
        return;
    } else if (current == lexe::gui::WizardStep::Build) {
        start_build(st);
        return; // build drives the stack directly
    }

    ++st->step;
    update_step(st);
}

// --- drag and drop ----------------------------------------------------------

/// A source folder dropped onto the window.
///
/// The WINDOW is the drop target rather than the Source page, because dropping
/// a folder is how someone says "package THIS instead" — and having to
/// navigate back to step 1 before the gesture would work defeats the point of
/// the gesture. Everything after Source is derived from the source folder (the
/// dependency list, the entrypoint list, the detected architecture), so a drop
/// returns to step 1 and re-runs detection from there.
void on_drag_data_received(GtkWidget*, GdkDragContext*, gint, gint,
                           GtkSelectionData* data, guint, guint,
                           gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);

    // A second folder dropped while the first is still being read would leave
    // two detection workers writing st->detection at once. Detection disables
    // Next/Back for exactly that reason, but a drop target is not a button and
    // insensitivity does not cover it, so refuse explicitly.
    if (st->detecting) {
        set_banner(st, false,
                   "Still inspecting the folder you dropped a moment ago — "
                   "wait for that to finish, then drop again.");
        return;
    }
    // The same reason one stage later: the build worker MOVES st->detection
    // into the build report, so a detection started underneath it would be
    // writing the object the build is reading.
    if (st->building) {
        set_banner(st, false,
                   "A build is running. Wait for it to finish, then drop the "
                   "next folder.");
        return;
    }

    std::vector<fs::path> local;
    int non_local = 0;
    if (gchar** uris = gtk_selection_data_get_uris(data)) {
        for (gchar** uri = uris; *uri != nullptr; ++uri) {
            // g_filename_from_uri is what makes this honest about what was
            // dropped: an http:// or a gvfs trash:// URI has no local path, and
            // packaging silently needs one.
            gchar* filename = g_filename_from_uri(*uri, nullptr, nullptr);
            if (filename == nullptr) {
                ++non_local;
                continue;
            }
            local.emplace_back(filename);
            g_free(filename);
        }
        g_strfreev(uris);
    }
    if (local.empty() && non_local > 0) {
        set_banner(st, false,
                   "That is not a folder on this machine. Lexe packages local "
                   "files, so download or mount it first, then drop the folder "
                   "it landed in.");
        return;
    }

    const lexe::gui::DropDecision decision = lexe::gui::decide_drop(local);
    if (!decision.accepted) {
        set_banner(st, false, decision.message);
        return;
    }

    // A drop is also a way OUT of the first-run welcome screen; without this
    // detection would run behind a page that has no Back/Next on it.
    leave_welcome(st);
    st->step = 0;
    update_step(st); // repaints the step strip and clears the old banner
    st->folder = decision.folder;
    path_picker_set(&st->source_picker, decision.folder);
    set_banner(st, true, decision.message);
    // The same asynchronous detection the Next button runs — one code path,
    // off the UI thread, advancing the step from on_detection_finished. A drop
    // that ran its own synchronous scan would freeze the window it was dropped
    // on.
    begin_detection(st);
}

// --- result-page actions ----------------------------------------------------

void on_open_folder(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    const fs::path dir = fs::path(st->report.output_package).parent_path();
    // Both failure paths were discarded: g_filename_to_uri got a nullptr
    // GError** and so did gtk_show_uri_on_window. On a machine with no
    // registered file-manager handler — a bare desktop, a headless session, a
    // container — the button did nothing at all, with no message, forever.
    // Tell the user, and give them the path so the button's failure does not
    // also lose the information it was going to show.
    GError* error = nullptr;
    gchar* uri = g_filename_to_uri(dir.string().c_str(), nullptr, &error);
    if (uri == nullptr) {
        set_banner(st, false,
                   "Could not open the output folder: " +
                       std::string(error != nullptr ? error->message
                                                    : "unknown error") +
                       ". It is at " + dir.string());
        if (error != nullptr) g_error_free(error);
        return;
    }
    const gboolean shown = gtk_show_uri_on_window(
        GTK_WINDOW(st->window), uri, GDK_CURRENT_TIME, &error);
    g_free(uri);
    if (shown == FALSE) {
        set_banner(st, false,
                   "No file manager is available to open the output folder. "
                   "It is at " + dir.string() +
                       (error != nullptr
                            ? std::string(" (") + error->message + ")"
                            : std::string()));
    }
    if (error != nullptr) g_error_free(error);
}

void on_copy_checksum(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    const std::string text = "sha256:" + st->built_checksum;
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD),
                           text.c_str(), -1);
}

void on_build_another(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    st->step = 0;
    st->detection_done = false;
    update_step(st);
}

void on_close_clicked(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    gtk_widget_destroy(st->window);
}

// --- pages ------------------------------------------------------------------

GtkWidget* new_page() {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 22);
    return box;
}

GtkWidget* build_source_page(BuilderState* st) {
    GtkWidget* box = new_page();
    gtk_box_pack_start(GTK_BOX(box),
                       body_label("Point the builder at the folder that holds "
                                  "your compiled application. Its contents "
                                  "become the package payload."),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(box),
        path_picker_build(&st->source_picker, "Application files folder",
                          "Choose folder\xe2\x80\xa6", "No folder chosen yet."),
        FALSE, FALSE, 0);
    g_signal_connect(st->source_picker.button, "clicked",
                     G_CALLBACK(on_choose_source_folder), st);

    GtkWidget* drop_hint = gtk_label_new(
        "Or drag the folder straight onto this window from your file manager \xe2\x80\x94 "
        "it is inspected the moment you drop it.");
    style::add_class(drop_hint, "lexe-muted");
    gtk_label_set_xalign(GTK_LABEL(drop_hint), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(drop_hint), TRUE);
    gtk_box_pack_start(GTK_BOX(box), drop_hint, FALSE, FALSE, 0);

    st->source_summary = body_label("Choose a folder, then press Next to detect "
                                    "the executable and dependencies.");
    gtk_box_pack_start(GTK_BOX(box), st->source_summary, FALSE, FALSE, 0);
    return page_scroller(box);
}

GtkWidget* build_deps_page(BuilderState* st) {
    GtkWidget* box = new_page();
    gtk_box_pack_start(GTK_BOX(box),
                       body_label("These dependencies were detected from the "
                                  "application's ELF metadata. In most cases the "
                                  "recommendations are what you want."),
                       FALSE, FALSE, 0);
    st->deps_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(box), st->deps_box, FALSE, FALSE, 0);
    return page_scroller(box);
}

GtkWidget* build_arch_page(BuilderState* st) {
    GtkWidget* box = new_page();
    gtk_box_pack_start(GTK_BOX(box), section_heading("Supported architectures"),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box),
                       body_label("Detected automatically from your binary; "
                                  "adjust if you ship multiple architectures."),
                       FALSE, FALSE, 0);
    st->arch_x86_check = gtk_check_button_new_with_label("x86-64 (Intel/AMD 64-bit)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(st->arch_x86_check), TRUE);
    st->arch_arm_check = gtk_check_button_new_with_label("ARM64 (aarch64)");
    gtk_box_pack_start(GTK_BOX(box), st->arch_x86_check, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), st->arch_arm_check, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box),
                       body_label("RISC-V and other architectures are planned; "
                                  "see docs/RUNTIME_PROFILES.md."),
                       FALSE, FALSE, 0);
    return page_scroller(box);
}

GtkWidget* build_metadata_page(BuilderState* st) {
    GtkWidget* box = new_page();
    GtkWidget* grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    int row = 0;
    st->name_entry = grid_entry(grid, row++, "Application name", "My Application");
    st->id_entry = grid_entry(grid, row++, "App ID", "com.example.app");
    gtk_widget_set_tooltip_text(
        st->id_entry, "A reverse-DNS identifier, e.g. com.example.app. It is the "
                      "durable identity used for install, update and trust.");
    st->version_entry = grid_entry(grid, row++, "Version", "1.0.0");
    gtk_entry_set_text(GTK_ENTRY(st->version_entry), "1.0.0");
    gtk_widget_set_tooltip_text(st->version_entry,
                               "A version like 1.0.0. Higher versions update "
                               "lower ones (FORMAT-0.1 §8).");
    st->publisher_entry = grid_entry(grid, row++, "Publisher name", "Example Corp");
    gtk_widget_set_tooltip_text(
        st->publisher_entry, "A display name. It is NOT verified — a signature "
                             "proves key continuity, not real-world identity.");
    st->website_entry = grid_entry(grid, row++, "Website (optional)",
                                   "https://example.com");
    st->description_entry =
        grid_entry(grid, row++, "Description (optional)", "A short description");
    // Say what actually happens to it. The 0.1 manifest has no description
    // field, so this is stored as forward-compatible metadata and no 0.1
    // surface displays it — a plain "Description" label promises otherwise.
    gtk_widget_set_tooltip_text(
        st->description_entry,
        "Stored in the package as forward-compatible metadata. No 0.1 surface "
        "displays it yet; the installer shows the Name and Publisher.");
    st->categories_entry =
        grid_entry(grid, row++, "Categories (optional)", "Utility, Development");

    GtkWidget* entry_lab = gtk_label_new("Entrypoint");
    gtk_label_set_xalign(GTK_LABEL(entry_lab), 0.0f);
    gtk_grid_attach(GTK_GRID(grid), entry_lab, 0, row, 1, 1);
    st->entrypoint_combo = gtk_combo_box_text_new();
    gtk_widget_set_hexpand(st->entrypoint_combo, TRUE);
    gtk_grid_attach(GTK_GRID(grid), st->entrypoint_combo, 1, row++, 1, 1);
    gtk_box_pack_start(GTK_BOX(box), grid, FALSE, FALSE, 0);

    st->icon_note = body_label("");
    gtk_box_pack_start(GTK_BOX(box), st->icon_note, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(box), section_heading("Permissions"), FALSE,
                       FALSE, 0);
    st->perm_network_check =
        gtk_check_button_new_with_label("Network access");
    st->perm_userfiles_check =
        gtk_check_button_new_with_label("Access to files the user selects");
    gtk_box_pack_start(GTK_BOX(box), st->perm_network_check, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), st->perm_userfiles_check, FALSE, FALSE, 0);
    return page_scroller(box);
}

/// Grey out whichever signing control the chosen option does not use, so the
/// page cannot show two live inputs when only one of them will be read.
void on_signing_choice_toggled(GtkToggleButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    const gboolean generating =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->key_generate_radio));
    gtk_widget_set_sensitive(st->generated_key_entry, generating);
    gtk_widget_set_sensitive(st->existing_key_picker.root, !generating);
}

GtkWidget* build_signing_page(BuilderState* st) {
    GtkWidget* box = new_page();
    gtk_box_pack_start(GTK_BOX(box), section_heading("Sign the application"),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(box),
        body_label("Your signing key is the application's durable identity — "
                   "every future update must be signed with it. Keep it safe "
                   "and out of version control."),
        FALSE, FALSE, 0);
    st->key_generate_radio =
        gtk_radio_button_new_with_label(nullptr, "Generate a new signing key");
    st->generated_key_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(st->generated_key_entry),
                                   "where to write the new key (optional)");
    st->key_existing_radio = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(st->key_generate_radio), "Use an existing key file");
    // The same treatment as the source folder: which key file signs this
    // package is exactly as consequential as which folder is packaged, and the
    // combo it replaces showed only a basename — every project's key is called
    // key.json, so the control was effectively blank.
    GtkWidget* key_card =
        path_picker_build(&st->existing_key_picker, "Signing key file",
                          "Choose key file\xe2\x80\xa6", "No key file chosen yet.");
    g_signal_connect(st->existing_key_picker.button, "clicked",
                     G_CALLBACK(on_choose_key_file), st);
    gtk_box_pack_start(GTK_BOX(box), st->key_generate_radio, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), st->generated_key_entry, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), st->key_existing_radio, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), key_card, FALSE, FALSE, 0);
    // Only the SELECTED option's control stays live. Both were enabled at once,
    // so the page showed a key-file chooser and a "where to write the new key"
    // box side by side with nothing to say which one the build would use —
    // and filling in the ignored one had no effect and no explanation.
    g_signal_connect(st->key_generate_radio, "toggled",
                     G_CALLBACK(on_signing_choice_toggled), st);
    on_signing_choice_toggled(nullptr, st); // set the initial state
    gtk_box_pack_start(
        GTK_BOX(box),
        body_label("Publisher certification (e.g. Usha Corporation of America) "
                   "is a separate, future concept — a developer signature is "
                   "never presented as an external certification."),
        FALSE, FALSE, 0);
    return page_scroller(box);
}

GtkWidget* build_output_page(BuilderState* st) {
    GtkWidget* box = new_page();
    gtk_box_pack_start(GTK_BOX(box), section_heading("Runtime profile"), FALSE,
                       FALSE, 0);
    st->profile_combo = gtk_combo_box_text_new();
    for (const lexe::RuntimeProfileInfo& p : lexe::runtime_profiles()) {
        const std::string label = p.name + " — " + p.portability + " portability";
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st->profile_combo),
                                       label.c_str());
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(st->profile_combo), 0);
    gtk_widget_set_tooltip_text(
        st->profile_combo,
        "The portability contract this package targets. Core Portable is the "
        "default and is verified against Tux32 Core 1.");
    gtk_box_pack_start(GTK_BOX(box), st->profile_combo, FALSE, FALSE, 0);

    // A plain-language explanation that follows the selected profile (WS2).
    st->profile_explanation = body_label(
        lexe::gui::profile_explanation_text(lexe::RuntimeProfile::CorePortable)
            .c_str());
    gtk_box_pack_start(GTK_BOX(box), st->profile_explanation, FALSE, FALSE, 0);
    g_signal_connect(st->profile_combo, "changed",
                     G_CALLBACK(on_profile_changed), st);

    gtk_box_pack_start(GTK_BOX(box), section_heading("Output package"), FALSE,
                       FALSE, 0);
    st->output_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(st->output_entry),
                                   "output .lexe path (default: ~/<id>.lexe)");
    gtk_widget_set_tooltip_text(st->output_entry,
                               "Where to write the signed .lexe. Leave blank to "
                               "use ~/<app-id>.lexe.");
    gtk_box_pack_start(GTK_BOX(box), st->output_entry, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box),
                       body_label(lexe::gui::verification_note().c_str()), FALSE,
                       FALSE, 0);
    return page_scroller(box);
}

GtkWidget* build_build_page(BuilderState* st) {
    GtkWidget* box = new_page();
    gtk_box_pack_start(GTK_BOX(box), section_heading("Ready to build"), FALSE,
                       FALSE, 0);
    st->build_summary = body_label("");
    gtk_box_pack_start(GTK_BOX(box), st->build_summary, FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(box),
        body_label("Press Build to analyze, collect dependencies, generate the "
                   "manifest, sign and verify the package."),
        FALSE, FALSE, 0);
    return page_scroller(box);
}

GtkWidget* build_progress_page(BuilderState* st) {
    GtkWidget* box = new_page();
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    st->spinner = gtk_spinner_new();
    gtk_widget_set_size_request(st->spinner, 48, 48);
    gtk_box_pack_start(GTK_BOX(box), st->spinner, FALSE, FALSE, 0);
    st->progress_label = body_label("Building and signing your package…");
    gtk_label_set_xalign(GTK_LABEL(st->progress_label), 0.5f);
    gtk_box_pack_start(GTK_BOX(box), st->progress_label, FALSE, FALSE, 0);

    // The meaningful build stages — never raw compiler/packer logs (DX1).
    std::string stages;
    for (const std::string& s : lexe::gui::build_stages()) {
        stages += (stages.empty() ? "" : "  →  ") + s;
    }
    GtkWidget* stage_label = body_label(stages.c_str());
    gtk_label_set_xalign(GTK_LABEL(stage_label), 0.5f);
    gtk_widget_set_sensitive(stage_label, FALSE); // rendered as muted caption
    gtk_box_pack_start(GTK_BOX(box), stage_label, FALSE, FALSE, 0);
    return box;
}

GtkWidget* build_result_page(BuilderState* st) {
    GtkWidget* box = new_page();
    st->result_heading = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(st->result_heading), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), st->result_heading, FALSE, FALSE, 0);

    st->result_report = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(st->result_report), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(st->result_report), TRUE);
    gtk_label_set_line_wrap(GTK_LABEL(st->result_report), TRUE);
    GtkWidget* mono_frame = gtk_frame_new(nullptr);
    gtk_container_add(GTK_CONTAINER(mono_frame), st->result_report);
    gtk_box_pack_start(GTK_BOX(box), page_scroller(mono_frame), TRUE, TRUE, 0);

    GtkWidget* buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget* open_btn = gtk_button_new_with_label("Open output folder");
    GtkWidget* copy_btn = gtk_button_new_with_label("Copy checksum");
    GtkWidget* another_btn = gtk_button_new_with_label("Build another");
    GtkWidget* close_btn = gtk_button_new_with_label("Close");
    g_signal_connect(open_btn, "clicked", G_CALLBACK(on_open_folder), st);
    g_signal_connect(copy_btn, "clicked", G_CALLBACK(on_copy_checksum), st);
    g_signal_connect(another_btn, "clicked", G_CALLBACK(on_build_another), st);
    g_signal_connect(close_btn, "clicked", G_CALLBACK(on_close_clicked), st);
    gtk_box_pack_start(GTK_BOX(buttons), open_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(buttons), copy_btn, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(buttons), close_btn, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(buttons), another_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), buttons, FALSE, FALSE, 0);
    return box;
}

// First-run welcome (DX8): dismiss it, remembering the choice if asked.
void on_welcome_continue(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    if (st->welcome_dont_show != nullptr &&
        gtk_toggle_button_get_active(
            GTK_TOGGLE_BUTTON(st->welcome_dont_show)) == TRUE) {
        try {
            lexe::gui::mark_welcome_seen(lexe::Paths::detect());
        } catch (const std::exception&) {
            // best-effort persistence
        }
    }
    leave_welcome(st);
    st->step = 0;
    update_step(st);
}

GtkWidget* build_welcome_page(BuilderState* st) {
    // The FIRST screen anyone ever sees, and the one that was left on widget
    // defaults while every wizard step behind it was restyled — so a first run
    // looked exactly like it always had. It gets the same language as the rest:
    // title from the type scale, the explanation in a card, and the one action
    // carrying the accent.
    GtkWidget* box = new_page();
    gtk_widget_set_margin_top(box, 8);

    GtkWidget* heading = gtk_label_new("Welcome to Lexe Builder");
    style::add_class(heading, "lexe-title");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);

    GtkWidget* tagline =
        gtk_label_new("Turn a folder of compiled files into a signed .lexe "
                      "package.");
    style::add_class(tagline, "lexe-subtitle");
    gtk_label_set_xalign(GTK_LABEL(tagline), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(tagline), TRUE);
    gtk_box_pack_start(GTK_BOX(box), tagline, FALSE, FALSE, 0);

    GtkWidget* card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    style::add_class(card, "lexe-card");
    GtkWidget* body = body_label(lexe::gui::welcome_body().c_str());
    gtk_box_pack_start(GTK_BOX(card), body, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), page_scroller(card), TRUE, TRUE, 0);

    st->welcome_dont_show =
        gtk_check_button_new_with_label("Don't show this again");
    gtk_box_pack_start(GTK_BOX(box), st->welcome_dont_show, FALSE, FALSE, 0);

    GtkWidget* row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget* start = gtk_button_new_with_label("Get started");
    style::add_class(start, "lexe-primary");
    g_signal_connect(start, "clicked", G_CALLBACK(on_welcome_continue), st);
    gtk_box_pack_end(GTK_BOX(row), start, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);
    return box;
}

// Show the welcome page and hide the wizard chrome until it is dismissed.
void show_welcome(BuilderState* st) {
    st->welcome_visible = true;
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "welcome");
    gtk_label_set_text(GTK_LABEL(st->step_counter), "");
    gtk_label_set_text(GTK_LABEL(st->step_title), "");
    gtk_label_set_text(GTK_LABEL(st->step_subtitle), "");
    gtk_widget_hide(st->back_button);
    gtk_widget_hide(st->next_button);
    // Hide the wizard chrome outright rather than blanking its labels. Emptied,
    // the step strip and the action bar are still drawn — two shaded bands with
    // nothing in them, top and bottom of the first screen anyone ever sees.
    //
    // What is hidden is the step TEXT, not the strip that carries it: the theme
    // control lives in that strip, and the first screen anyone sees is the one
    // most likely to be the wrong brightness for the desk it is sitting on. A
    // toggle only reachable from step 1 is not reachable from here.
    if (st->step_header != nullptr) gtk_widget_hide(st->step_header);
    if (st->footer != nullptr) gtk_widget_hide(st->footer);
    set_banner(st, true, "");
}

void build_ui(BuilderState* st) {
    st->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    const std::string title = "Lexe Builder " + lexe::version::runtime_string();
    gtk_window_set_title(GTK_WINDOW(st->window), title.c_str());
    gtk_window_set_default_size(GTK_WINDOW(st->window), 780, 700);
    gtk_container_set_border_width(GTK_CONTAINER(st->window), 0);
    g_signal_connect(st->window, "destroy", G_CALLBACK(gtk_main_quit), nullptr);

    GtkWidget* root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(st->window), root);

    // Header: a lit strip carrying the step text on the left and the theme
    // control on the right, like the installer's banner and both action bars —
    // flat content between two subtly shaded edges. Sizing comes from the
    // stylesheet's type scale rather than Pango attributes, so the wizard's
    // title and the installer's title are the same size by construction
    // instead of by coincidence.
    //
    // The strip and the step text inside it are two widgets on purpose: the
    // welcome screen hides the text and keeps the strip, so the theme control
    // is reachable from the very first screen.
    GtkWidget* header_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
    style::add_class(header_bar, "lexe-stepbar");
    GtkWidget* header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    st->step_header = header;
    gtk_widget_set_hexpand(header, TRUE);
    st->step_counter = gtk_label_new("Step 1 of 7");
    style::add_class(st->step_counter, "lexe-muted");
    gtk_label_set_xalign(GTK_LABEL(st->step_counter), 0.0f);
    st->step_title = gtk_label_new(nullptr);
    style::add_class(st->step_title, "lexe-title");
    gtk_label_set_xalign(GTK_LABEL(st->step_title), 0.0f);
    st->step_subtitle = gtk_label_new(nullptr);
    style::add_class(st->step_subtitle, "lexe-subtitle");
    gtk_label_set_xalign(GTK_LABEL(st->step_subtitle), 0.0f);
    gtk_box_pack_start(GTK_BOX(header), st->step_counter, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header), st->step_title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header), st->step_subtitle, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header_bar), header, TRUE, TRUE, 0);

    // Theme: three states, not a two-way switch. "System" has to be one of
    // them and has to be the default — a desktop that follows the time of day
    // is common, and a builder that latched to whatever it happened to be at
    // first launch would be the one window not moving with it.
    GtkWidget* theme_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_valign(theme_box, GTK_ALIGN_CENTER);
    // A mnemonic, and the mnemonic-widget RELATION that goes with it: Alt+T
    // reaches the control, and ATK derives the accessible name from the
    // relation, so a screen reader announces "Theme" rather than just reading
    // back whichever value happens to be selected. The installer's control does
    // the same; the two must not diverge on the same setting.
    GtkWidget* theme_caption = gtk_label_new_with_mnemonic("_Theme");
    style::add_class(theme_caption, "lexe-section-heading");
    gtk_label_set_xalign(GTK_LABEL(theme_caption), 0.0f);
    st->theme_combo = gtk_combo_box_text_new();
    gtk_label_set_mnemonic_widget(GTK_LABEL(theme_caption), st->theme_combo);
    for (const std::string& choice : lexe::gui::theme_choices()) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st->theme_combo),
                                       lexe::gui::theme_label(choice).c_str());
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(st->theme_combo),
                             lexe::gui::theme_choice_index(st->theme));
    gtk_widget_set_tooltip_text(
        st->theme_combo,
        "System follows your desktop. The choice is saved as the `theme` "
        "setting \xe2\x80\x94 the same one `lexe config set theme` reads and writes.");
    // Connected AFTER the initial selection: restoring the saved theme must not
    // immediately write it straight back out again.
    g_signal_connect(st->theme_combo, "changed", G_CALLBACK(on_theme_changed),
                     st);
    gtk_box_pack_start(GTK_BOX(theme_box), theme_caption, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(theme_box), st->theme_combo, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(header_bar), theme_box, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(root), header_bar, FALSE, FALSE, 0);

    // Stack of pages.
    st->stack = gtk_stack_new();
    gtk_widget_set_vexpand(st->stack, TRUE);
    gtk_stack_add_named(GTK_STACK(st->stack), build_source_page(st), "step0");
    gtk_stack_add_named(GTK_STACK(st->stack), build_deps_page(st), "step1");
    gtk_stack_add_named(GTK_STACK(st->stack), build_arch_page(st), "step2");
    gtk_stack_add_named(GTK_STACK(st->stack), build_metadata_page(st), "step3");
    gtk_stack_add_named(GTK_STACK(st->stack), build_signing_page(st), "step4");
    gtk_stack_add_named(GTK_STACK(st->stack), build_output_page(st), "step5");
    gtk_stack_add_named(GTK_STACK(st->stack), build_build_page(st), "step6");
    gtk_stack_add_named(GTK_STACK(st->stack), build_progress_page(st), "progress");
    gtk_stack_add_named(GTK_STACK(st->stack), build_result_page(st), "result");
    gtk_stack_add_named(GTK_STACK(st->stack), build_welcome_page(st), "welcome");
    gtk_box_pack_start(GTK_BOX(root), st->stack, TRUE, TRUE, 0);

    // Footer: banner + Back/Next.
    GtkWidget* footer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    st->footer = footer;
    style::add_class(footer, "lexe-actionbar");
    st->banner_label = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(st->banner_label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(st->banner_label), TRUE);
    gtk_box_pack_start(GTK_BOX(footer), st->banner_label, TRUE, TRUE, 0);
    st->back_button = gtk_button_new_with_label("Back");
    st->next_button = gtk_button_new_with_label("Next");
    style::add_class(st->next_button, "lexe-primary");
    g_signal_connect(st->back_button, "clicked", G_CALLBACK(on_back_clicked), st);
    g_signal_connect(st->next_button, "clicked", G_CALLBACK(on_next_clicked), st);
    gtk_box_pack_start(GTK_BOX(footer), st->back_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(footer), st->next_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), footer, FALSE, FALSE, 0);

    // Drag and drop: a source folder dropped anywhere on the window. Only
    // text/uri-list is accepted — it is what every file manager offers for a
    // dragged folder, and it is the only one that names a filesystem path.
    //
    // GTK_DEST_DEFAULT_ALL also calls gtk_drag_finish() for us once the handler
    // returns; finishing the same drop a second time by hand is a GTK warning,
    // and scripts/gui-smoke.sh fails the build on any of those.
    static GtkTargetEntry drop_targets[] = {
        {const_cast<gchar*>("text/uri-list"), 0, 0}};
    gtk_drag_dest_set(st->window, GTK_DEST_DEFAULT_ALL, drop_targets, 1,
                      GDK_ACTION_COPY);
    g_signal_connect(st->window, "drag-data-received",
                     G_CALLBACK(on_drag_data_received), st);

    update_step(st);
}

} // namespace

int main(int argc, char** argv) {
    gtk_init(&argc, &argv);

    // The desktop's OWN dark preference, read before style::apply() has had a
    // chance to write to it. style::apply() stores the theme it resolved into
    // gtk-application-prefer-dark-theme, and resolve_dark(System) reads that
    // same flag back to decide what the desktop wants — so without this
    // snapshot, a session that has been Dark once answers "the desktop prefers
    // dark" from then on, and switching back to System would stay dark on a
    // light desktop. apply_theme() restores it.
    gboolean desktop_prefers_dark = FALSE;
    if (GtkSettings* gtk_settings = gtk_settings_get_default()) {
        g_object_get(gtk_settings, "gtk-application-prefer-dark-theme",
                     &desktop_prefers_dark, nullptr);
    }

    // The persisted `theme` setting decides how the window is drawn from its
    // first frame: styling it light and then correcting it once the widgets
    // exist is a visible flash of the wrong theme on every launch.
    const std::string theme = startup_theme();
    style::apply(style::theme_from_string(theme));

    // Body text is selectable so a user can copy a fingerprint or an ID. GTK
    // pairs that with gtk-label-select-on-focus, which makes the first
    // focusable label select ALL of its text the moment the window opens — one
    // line comes up highlighted as if the user had dragged over it. Turn the
    // behaviour off; the labels stay selectable by hand.
    if (GtkSettings* settings = gtk_settings_get_default()) {
        g_object_set(settings, "gtk-label-select-on-focus", FALSE, nullptr);
    }
    BuilderState* st = new BuilderState();
    st->theme = theme;
    st->desktop_prefers_dark = desktop_prefers_dark;
    build_ui(st);
    gtk_widget_show_all(st->window);
    // First run: greet the developer once (DX8); otherwise start the wizard.
    bool welcome = false;
    try {
        welcome = lexe::gui::should_show_welcome(lexe::Paths::detect());
    } catch (const std::exception&) {
        welcome = false;
    }
    if (welcome) {
        show_welcome(st);
    } else {
        update_step(st); // re-apply the initial page after show_all
    }
    gtk_main();
    return 0;
}

#endif // !LEXE_GUI_VIEWMODEL_ONLY
