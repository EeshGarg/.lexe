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
#include "core/runtime_profile.hpp"
#include "core/tux32.hpp"
#include "core/version.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
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

namespace fs = std::filesystem;

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

    // Step 1 — Source.
    GtkWidget* folder_chooser = nullptr;
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
    GtkWidget* existing_key_chooser = nullptr;
    // Step 6 — Output.
    GtkWidget* output_entry = nullptr;
    GtkWidget* profile_combo = nullptr;
    // Step 7 — Build summary + progress.
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

    // Captured on Build (main thread) → worker.
    lexe::gui::BuilderForm form;
    bool generate_key = true;
    std::string existing_key_path;
    std::string generated_key_path;
    std::string output_path;

    // Results (worker → main).
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

void set_banner(BuilderState* st, bool ok, const std::string& text) {
    if (text.empty()) {
        gtk_label_set_text(GTK_LABEL(st->banner_label), "");
        return;
    }
    gchar* escaped = g_markup_escape_text(text.c_str(), -1);
    gchar* markup = g_strdup_printf(
        "<span weight=\"bold\" foreground=\"%s\">%s</span>",
        ok ? "#1a7f37" : "#b00020", escaped);
    gtk_label_set_markup(GTK_LABEL(st->banner_label), markup);
    g_free(markup);
    g_free(escaped);
}

// --- small widget helpers ---------------------------------------------------

GtkWidget* section_heading(const char* text) {
    GtkWidget* label = gtk_label_new(nullptr);
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

// --- form gathering ---------------------------------------------------------

lexe::RuntimeProfile selected_profile(BuilderState* st) {
    switch (gtk_combo_box_get_active(GTK_COMBO_BOX(st->profile_combo))) {
    case 1: return lexe::RuntimeProfile::ForwardRuntime;
    case 2: return lexe::RuntimeProfile::NativeCapture;
    default: return lexe::RuntimeProfile::CorePortable;
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
        gtk_box_pack_start(GTK_BOX(st->deps_box),
                           body_label("No shared-library dependencies were "
                                      "detected (a static or script app)."),
                           FALSE, FALSE, 0);
    }
    for (const lexe::gui::DependencyRow& row : rows) {
        GtkWidget* frame = gtk_frame_new(nullptr);
        GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        gtk_container_set_border_width(GTK_CONTAINER(box), 6);
        const std::string title = row.soname + "  —  " + row.handling;
        GtkWidget* head = gtk_label_new(nullptr);
        gchar* esc = g_markup_escape_text(title.c_str(), -1);
        gchar* markup = g_strdup_printf(
            "<span weight=\"bold\" foreground=\"%s\">%s</span>",
            row.warn ? "#b06000" : "#1a1a1a", esc);
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

/// Run automatic detection on the chosen folder and prefill the wizard.
void run_detection(BuilderState* st) {
    st->detection = lexe::gui::detect_source(fs::path(st->folder));
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
    if (!st->detection.entrypoints.empty()) {
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
                    "Core Portable contract. Fix the items above, or choose a "
                    "different runtime profile (Step 3).";
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
            if (keyfile.has_parent_path()) {
                std::error_code ec;
                fs::create_directories(keyfile.parent_path(), ec);
            }
            key = lexe::crypto::generate_keypair();
            lexe::crypto::write_keyfile(keyfile, key);
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
    gtk_spinner_stop(GTK_SPINNER(st->spinner));
    if (!st->build_ok) {
        set_banner(st, false, "Build failed: " + st->build_error);
        gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "step6");
        gtk_widget_set_sensitive(st->next_button, TRUE);
        gtk_widget_set_sensitive(st->back_button, TRUE);
        return G_SOURCE_REMOVE;
    }
    gchar* heading = g_strdup_printf(
        "<span size=\"large\" weight=\"bold\" foreground=\"#1a7f37\">Build "
        "succeeded</span>");
    gtk_label_set_markup(GTK_LABEL(st->result_heading), heading);
    g_free(heading);
    gtk_label_set_text(GTK_LABEL(st->result_report),
                       lexe::render_build_report_text(st->report).c_str());
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
        gchar* chosen = gtk_file_chooser_get_filename(
            GTK_FILE_CHOOSER(st->existing_key_chooser));
        st->existing_key_path = chosen != nullptr ? std::string(chosen) : "";
        if (chosen != nullptr) g_free(chosen);
        if (st->existing_key_path.empty()) {
            set_banner(st, false, "Choose the signing key file, or switch to "
                                  "generating a new key.");
            return;
        }
    }
    st->output_path = resolve_output_path(st, st->form.app_id);

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
        gchar* path =
            gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(st->folder_chooser));
        st->folder = path != nullptr ? std::string(path) : std::string();
        if (path != nullptr) g_free(path);
        if (st->folder.empty()) {
            set_banner(st, false,
                       "Choose the folder that holds your application's files.");
            return;
        }
        run_detection(st);
    } else if (current == lexe::gui::WizardStep::Build) {
        start_build(st);
        return; // build drives the stack directly
    }

    ++st->step;
    update_step(st);
}

// --- result-page actions ----------------------------------------------------

void on_open_folder(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    const fs::path dir = fs::path(st->report.output_package).parent_path();
    gchar* uri = g_filename_to_uri(dir.string().c_str(), nullptr, nullptr);
    if (uri != nullptr) {
        gtk_show_uri_on_window(GTK_WINDOW(st->window), uri, GDK_CURRENT_TIME,
                               nullptr);
        g_free(uri);
    }
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
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    return box;
}

GtkWidget* build_source_page(BuilderState* st) {
    GtkWidget* box = new_page();
    gtk_box_pack_start(GTK_BOX(box),
                       body_label("Point the builder at the folder that holds "
                                  "your compiled application. Its contents "
                                  "become the package payload."),
                       FALSE, FALSE, 0);
    st->folder_chooser = gtk_file_chooser_button_new(
        "Application files folder", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
    gtk_box_pack_start(GTK_BOX(box), st->folder_chooser, FALSE, FALSE, 0);
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
    st->version_entry = grid_entry(grid, row++, "Version", "1.0.0");
    gtk_entry_set_text(GTK_ENTRY(st->version_entry), "1.0.0");
    st->publisher_entry = grid_entry(grid, row++, "Publisher name", "Example Corp");
    st->website_entry = grid_entry(grid, row++, "Website (optional)",
                                   "https://example.com");
    st->description_entry =
        grid_entry(grid, row++, "Description (optional)", "A short description");
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
    st->existing_key_chooser = gtk_file_chooser_button_new(
        "Signing key (key.json)", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_box_pack_start(GTK_BOX(box), st->key_generate_radio, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), st->generated_key_entry, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), st->key_existing_radio, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), st->existing_key_chooser, FALSE, FALSE, 0);
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
    gtk_box_pack_start(GTK_BOX(box), st->profile_combo, FALSE, FALSE, 0);
    gtk_box_pack_start(
        GTK_BOX(box),
        body_label("Core Portable is the default. Native Capture has reduced "
                   "portability; Forward Runtime warns when a newer runtime is "
                   "required."),
        FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(box), section_heading("Output package"), FALSE,
                       FALSE, 0);
    st->output_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(st->output_entry),
                                   "output .lexe path (default: ~/<id>.lexe)");
    gtk_box_pack_start(GTK_BOX(box), st->output_entry, FALSE, FALSE, 0);
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

void build_ui(BuilderState* st) {
    st->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    const std::string title = "Lexe Builder " + lexe::version::runtime_string();
    gtk_window_set_title(GTK_WINDOW(st->window), title.c_str());
    gtk_window_set_default_size(GTK_WINDOW(st->window), 720, 620);
    gtk_container_set_border_width(GTK_CONTAINER(st->window), 0);
    g_signal_connect(st->window, "destroy", G_CALLBACK(gtk_main_quit), nullptr);

    GtkWidget* root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(st->window), root);

    // Header: step counter + title + subtitle.
    GtkWidget* header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_container_set_border_width(GTK_CONTAINER(header), 12);
    st->step_counter = gtk_label_new("Step 1 of 7");
    gtk_label_set_xalign(GTK_LABEL(st->step_counter), 0.0f);
    st->step_title = gtk_label_new(nullptr);
    {
        GtkWidget* t = st->step_title;
        PangoAttrList* attrs = pango_attr_list_new();
        pango_attr_list_insert(attrs, pango_attr_scale_new(PANGO_SCALE_X_LARGE));
        pango_attr_list_insert(attrs, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
        gtk_label_set_attributes(GTK_LABEL(t), attrs);
        pango_attr_list_unref(attrs);
        gtk_label_set_xalign(GTK_LABEL(t), 0.0f);
    }
    st->step_subtitle = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(st->step_subtitle), 0.0f);
    gtk_box_pack_start(GTK_BOX(header), st->step_counter, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header), st->step_title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header), st->step_subtitle, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), header, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),
                       FALSE, FALSE, 0);

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
    gtk_box_pack_start(GTK_BOX(root), st->stack, TRUE, TRUE, 0);

    // Footer: banner + Back/Next.
    gtk_box_pack_start(GTK_BOX(root), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),
                       FALSE, FALSE, 0);
    GtkWidget* footer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(footer), 12);
    st->banner_label = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(st->banner_label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(st->banner_label), TRUE);
    gtk_box_pack_start(GTK_BOX(footer), st->banner_label, TRUE, TRUE, 0);
    st->back_button = gtk_button_new_with_label("Back");
    st->next_button = gtk_button_new_with_label("Next");
    g_signal_connect(st->back_button, "clicked", G_CALLBACK(on_back_clicked), st);
    g_signal_connect(st->next_button, "clicked", G_CALLBACK(on_next_clicked), st);
    gtk_box_pack_start(GTK_BOX(footer), st->back_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(footer), st->next_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), footer, FALSE, FALSE, 0);

    update_step(st);
}

} // namespace

int main(int argc, char** argv) {
    gtk_init(&argc, &argv);
    BuilderState* st = new BuilderState();
    build_ui(st);
    gtk_widget_show_all(st->window);
    update_step(st); // re-apply the initial page after show_all
    gtk_main();
    return 0;
}

#endif // !LEXE_GUI_VIEWMODEL_ONLY
