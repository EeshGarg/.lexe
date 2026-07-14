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

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
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
    doc["install"] = std::move(install);

    const std::vector<std::string> permissions = selected_permissions(form);
    if (!permissions.empty()) {
        doc["permissions"] = permissions;
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

} // namespace lexe::gui

// ===========================================================================
// GTK 3 application. Compiled only when <gtk/gtk.h> is available — the
// Linux-only `lexe-builder` target. Never seen by non-GTK builds.
// ===========================================================================
#ifndef LEXE_GUI_VIEWMODEL_ONLY

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/manifest.hpp"
#include "core/package.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"

#include <gtk/gtk.h>

#include <exception>

namespace {

namespace fs = std::filesystem;

/// Whole-application state, owned by main(). Widget pointers are only ever
/// touched on the GTK main thread; the plain-data fields captured on Build are
/// read by exactly one worker thread and its results read back on the main
/// thread only after the worker's final g_idle_add (which orders the accesses).
struct BuilderState {
    // Widgets (main thread only).
    GtkWidget* window = nullptr;
    GtkWidget* stack = nullptr;
    GtkWidget* banner_label = nullptr;
    GtkWidget* folder_chooser = nullptr;
    GtkWidget* id_entry = nullptr;
    GtkWidget* name_entry = nullptr;
    GtkWidget* version_entry = nullptr;
    GtkWidget* entrypoint_combo = nullptr;
    GtkWidget* publisher_entry = nullptr;
    GtkWidget* website_entry = nullptr;
    GtkWidget* arch_x86_check = nullptr;
    GtkWidget* arch_arm_check = nullptr;
    GtkWidget* perm_network_check = nullptr;
    GtkWidget* perm_userfiles_check = nullptr;
    GtkWidget* key_generate_radio = nullptr;
    GtkWidget* key_existing_radio = nullptr;
    GtkWidget* generated_key_entry = nullptr;
    GtkWidget* existing_key_chooser = nullptr;
    GtkWidget* output_entry = nullptr;
    GtkWidget* build_button = nullptr;
    GtkWidget* spinner = nullptr;
    GtkWidget* progress_label = nullptr;

    // Result page widgets.
    GtkWidget* result_status_label = nullptr;
    GtkWidget* result_path_label = nullptr;
    GtkWidget* result_pubkey_label = nullptr;
    GtkWidget* result_verify_label = nullptr;
    GtkWidget* result_keynote_label = nullptr;

    // Folder scan state (main thread).
    std::string folder;
    std::vector<std::string> entrypoints;

    // Captured on Build (main thread) -> worker.
    lexe::gui::BuilderForm form;
    bool generate_key = true;
    std::string existing_key_path;
    std::string generated_key_path; // where a fresh key is written
    std::string output_path;

    // Results (worker -> main).
    bool build_ok = false;
    std::string build_error;
    std::string built_path;
    std::string built_pubkey;
    bool verification_ok = false;
    std::string verification_detail;
    bool key_was_generated = false;
    std::string generated_key_written_path;
};

/// Trim ASCII whitespace off both ends.
std::string trim(const std::string& text) {
    const std::size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return std::string();
    const std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

/// Trimmed text of a GtkEntry.
std::string entry_text(GtkWidget* entry) {
    const gchar* text = gtk_entry_get_text(GTK_ENTRY(entry));
    return trim(text != nullptr ? std::string(text) : std::string());
}

/// Set the form-page banner (bold, red for errors, green for information).
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

// ----------------------------------------------------------- folder scanning

/// Repopulate the entrypoint combo from the freshly chosen folder.
void on_folder_chosen(GtkFileChooserButton* chooser, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    gchar* path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(chooser));
    st->folder = (path != nullptr) ? std::string(path) : std::string();
    if (path != nullptr) g_free(path);

    st->entrypoints = lexe::gui::enumerate_entrypoints(fs::path(st->folder));

    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(st->entrypoint_combo));
    for (const std::string& file : st->entrypoints) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st->entrypoint_combo),
                                       file.c_str());
    }
    if (!st->entrypoints.empty()) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(st->entrypoint_combo), 0);
        set_banner(st, true,
                   "Found " + std::to_string(st->entrypoints.size()) +
                       " file(s) in the folder. Pick the entrypoint below.");
    } else if (!st->folder.empty()) {
        set_banner(st, false,
                   "No files found in that folder — choose a folder that "
                   "contains your application's files.");
    }
}

/// Enable exactly the key input that matches the selected radio.
void on_key_mode_toggled(GtkToggleButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    const gboolean generate =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->key_generate_radio));
    gtk_widget_set_sensitive(st->generated_key_entry, generate);
    gtk_widget_set_sensitive(st->existing_key_chooser, !generate);
}

// ------------------------------------------------------------------ building

/// The output path: the entry when set, else $HOME/<id>.lexe.
std::string resolve_output_path(BuilderState* st) {
    const std::string text = entry_text(st->output_entry);
    if (!text.empty()) return text;
    const gchar* home = g_get_home_dir();
    const std::string base = st->form.app_id.empty() ? std::string("app")
                                                      : st->form.app_id;
    return (fs::path(home != nullptr ? home : ".") / (base + ".lexe")).string();
}

/// Gather the form widgets into the pure BuilderForm view-model struct.
lexe::gui::BuilderForm gather_form(BuilderState* st) {
    lexe::gui::BuilderForm form;
    form.app_id = entry_text(st->id_entry);
    form.name = entry_text(st->name_entry);
    form.version = entry_text(st->version_entry);
    form.publisher_name = entry_text(st->publisher_entry);
    form.publisher_website = entry_text(st->website_entry);
    gchar* entrypoint =
        gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(st->entrypoint_combo));
    form.entrypoint = (entrypoint != nullptr) ? std::string(entrypoint)
                                              : std::string();
    if (entrypoint != nullptr) g_free(entrypoint);
    form.arch_x86_64 =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->arch_x86_check));
    form.arch_aarch64 =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->arch_arm_check));
    form.perm_network =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->perm_network_check));
    form.perm_user_files_selected = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(st->perm_userfiles_check));
    form.available_entrypoints = st->entrypoints;
    return form;
}

gboolean on_build_finished(gpointer user_data);

/// Worker thread: the whole build. NO GTK calls — results land in BuilderState
/// and the main loop is notified via g_idle_add. No exception escapes.
gpointer build_worker(gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    std::string tmpdir;
    try {
        // 1. Resolve the signing key. The public key becomes the manifest's
        //    publisher.publicKey — the developer never types a key.
        lexe::crypto::KeyPair key;
        if (st->generate_key) {
            const fs::path keyfile(st->generated_key_path);
            if (keyfile.has_parent_path()) {
                std::error_code ec;
                fs::create_directories(keyfile.parent_path(), ec);
            }
            key = lexe::crypto::generate_keypair();
            lexe::crypto::write_keyfile(keyfile, key);
            st->key_was_generated = true;
            st->generated_key_written_path = keyfile.string();
        } else {
            key = lexe::crypto::read_keyfile(fs::path(st->existing_key_path));
            st->key_was_generated = false;
        }
        const std::string pubkey =
            lexe::crypto::encode_public_key(key.public_key);

        // 2. Construct + validate the manifest from the form.
        const std::string manifest_json =
            lexe::gui::build_manifest_json(st->form, pubkey);
        lexe::Manifest::parse(manifest_json); // throws on any §5 violation

        // 3. Write it to a temporary lexe.json.
        gchar* made = g_dir_make_tmp("lexe-builder-XXXXXX", nullptr);
        if (made == nullptr) {
            throw lexe::Error("could not create a temporary working directory");
        }
        tmpdir = made;
        g_free(made);
        const fs::path manifest_file = fs::path(tmpdir) / "lexe.json";
        lexe::util::spit(manifest_file, std::string_view(manifest_json));

        // 4. Pack the folder's contents as payload/ (FORMAT-0.1 §1).
        const fs::path output(st->output_path);
        if (output.has_parent_path()) {
            std::error_code ec;
            fs::create_directories(output.parent_path(), ec);
        }
        lexe::PackageWriter::Inputs inputs;
        inputs.payload_dir = fs::path(st->folder);
        inputs.manifest_file = manifest_file;
        lexe::PackageWriter::write(inputs, key, output);

        // 5. Verify what we just built (no architecture gate — a cross-arch
        //    build is legitimate).
        const lexe::VerificationReport report =
            lexe::verify_package(output, /*check_architecture=*/false);
        st->verification_ok = report.ok();
        if (report.ok()) {
            st->verification_detail = "OK";
        } else {
            const lexe::VerificationStage* failure = report.first_failure();
            st->verification_detail =
                failure != nullptr
                    ? failure->name + ": " + failure->detail
                    : std::string("unknown verification failure");
        }
        st->built_path = output.string();
        st->built_pubkey = pubkey;
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
        fs::remove_all(fs::path(tmpdir), ec); // best effort
    }
    g_idle_add(on_build_finished, st);
    return nullptr;
}

/// Main-loop continuation of build_worker.
gboolean on_build_finished(gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    gtk_spinner_stop(GTK_SPINNER(st->spinner));
    gtk_widget_set_sensitive(st->build_button, TRUE);

    if (!st->build_ok) {
        set_banner(st, false, "Build failed: " + st->build_error);
        gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "form");
        return G_SOURCE_REMOVE;
    }

    gtk_label_set_text(GTK_LABEL(st->result_status_label),
                       "Your signed .lexe package is ready.");
    gtk_label_set_text(GTK_LABEL(st->result_path_label),
                       ("Package: " + st->built_path).c_str());
    gtk_label_set_text(GTK_LABEL(st->result_pubkey_label),
                       ("Publisher public key:\n" + st->built_pubkey).c_str());
    const std::string verify_text =
        st->verification_ok
            ? std::string("Verification: OK — structure, manifest, signatures "
                          "and hashes all check out.")
            : "Verification: FAILED — " + st->verification_detail;
    gtk_label_set_text(GTK_LABEL(st->result_verify_label), verify_text.c_str());

    if (st->key_was_generated) {
        const std::string note =
            "A new signing key was generated at " +
            st->generated_key_written_path +
            "\nKeep this key safe — it is the identity of every future "
            "update. Do not commit it to version control.";
        gtk_label_set_text(GTK_LABEL(st->result_keynote_label), note.c_str());
        gtk_widget_show(st->result_keynote_label);
    } else {
        gtk_widget_hide(st->result_keynote_label);
    }

    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "result");
    return G_SOURCE_REMOVE;
}

void on_build_clicked(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);

    if (st->folder.empty()) {
        set_banner(st, false, "Choose the folder that holds your app files.");
        return;
    }
    st->form = gather_form(st);

    const lexe::gui::ValidationResult validation =
        lexe::gui::validate_form(st->form);
    if (!validation.ok) {
        set_banner(st, false, validation.error);
        return;
    }

    // Resolve the signing-key source (the actual keygen/read happens on the
    // worker thread).
    st->generate_key =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(st->key_generate_radio));
    st->output_path = resolve_output_path(st);
    if (st->generate_key) {
        std::string chosen = entry_text(st->generated_key_entry);
        if (chosen.empty()) {
            const fs::path output_dir = fs::path(st->output_path).parent_path();
            chosen = (output_dir / (st->form.app_id + ".key.json")).string();
        }
        st->generated_key_path = chosen;
    } else {
        gchar* keyfile =
            gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(st->existing_key_chooser));
        st->existing_key_path =
            (keyfile != nullptr) ? std::string(keyfile) : std::string();
        if (keyfile != nullptr) g_free(keyfile);
        if (st->existing_key_path.empty()) {
            set_banner(st, false,
                       "Choose an existing key file, or switch to \"Generate a "
                       "new key\".");
            return;
        }
    }

    set_banner(st, true, std::string());
    gtk_widget_set_sensitive(st->build_button, FALSE);
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "progress");
    gtk_spinner_start(GTK_SPINNER(st->spinner));

    GThread* thread = g_thread_new("lexe-build", build_worker, st);
    g_thread_unref(thread);
}

void on_window_destroy(GtkWidget*, gpointer) { gtk_main_quit(); }

void on_close_clicked(GtkButton*, gpointer) { gtk_main_quit(); }

void on_build_another_clicked(GtkButton*, gpointer user_data) {
    BuilderState* st = static_cast<BuilderState*>(user_data);
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "form");
}

// ------------------------------------------------------------------- layout

/// Attach a "Label: [widget]" row to a two-column grid.
void grid_add_row(GtkWidget* grid, int row, const char* label,
                  GtkWidget* widget) {
    GtkWidget* caption = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(caption), 0.0f);
    gtk_grid_attach(GTK_GRID(grid), caption, 0, row, 1, 1);
    gtk_widget_set_hexpand(widget, TRUE);
    gtk_grid_attach(GTK_GRID(grid), widget, 1, row, 1, 1);
}

/// A left-aligned, wrapped, selectable label appended to `box`.
GtkWidget* add_result_label(GtkWidget* box, bool selectable) {
    GtkWidget* label = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_selectable(GTK_LABEL(label), selectable ? TRUE : FALSE);
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
    return label;
}

GtkWidget* build_form_page(BuilderState* st) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);

    GtkWidget* heading = gtk_label_new(nullptr);
    gtk_label_set_markup(
        GTK_LABEL(heading),
        "<span size=\"large\" weight=\"bold\">Build a signed .lexe</span>");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);

    st->banner_label = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(st->banner_label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(st->banner_label), TRUE);
    gtk_box_pack_start(GTK_BOX(box), st->banner_label, FALSE, FALSE, 0);

    // App files folder.
    st->folder_chooser = gtk_file_chooser_button_new(
        "Select the app files folder", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
    g_signal_connect(st->folder_chooser, "file-set",
                     G_CALLBACK(on_folder_chosen), st);

    // Core form fields.
    GtkWidget* grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);

    st->id_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(st->id_entry), "com.example.app");
    st->name_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(st->name_entry), "Example App");
    st->version_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(st->version_entry), "1.0.0");
    st->entrypoint_combo = gtk_combo_box_text_new();
    st->publisher_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(st->publisher_entry),
                                   "Example Corporation");
    st->website_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(st->website_entry),
                                   "https://example.com (optional)");

    int row = 0;
    grid_add_row(grid, row++, "App files folder:", st->folder_chooser);
    grid_add_row(grid, row++, "App ID:", st->id_entry);
    grid_add_row(grid, row++, "Name:", st->name_entry);
    grid_add_row(grid, row++, "Version:", st->version_entry);
    grid_add_row(grid, row++, "Entrypoint:", st->entrypoint_combo);
    grid_add_row(grid, row++, "Publisher name:", st->publisher_entry);
    grid_add_row(grid, row++, "Publisher website:", st->website_entry);

    // Architectures.
    GtkWidget* arch_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    st->arch_x86_check = gtk_check_button_new_with_label("x86_64");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(st->arch_x86_check), TRUE);
    st->arch_arm_check = gtk_check_button_new_with_label("aarch64");
    gtk_box_pack_start(GTK_BOX(arch_box), st->arch_x86_check, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(arch_box), st->arch_arm_check, FALSE, FALSE, 0);
    grid_add_row(grid, row++, "Architectures:", arch_box);

    // Permissions.
    GtkWidget* perm_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    st->perm_network_check = gtk_check_button_new_with_label("network");
    st->perm_userfiles_check =
        gtk_check_button_new_with_label("user-files-selected");
    gtk_box_pack_start(GTK_BOX(perm_box), st->perm_network_check, FALSE, FALSE,
                       0);
    gtk_box_pack_start(GTK_BOX(perm_box), st->perm_userfiles_check, FALSE, FALSE,
                       0);
    grid_add_row(grid, row++, "Permissions:", perm_box);

    gtk_box_pack_start(GTK_BOX(box), grid, FALSE, FALSE, 0);

    // Signing key.
    GtkWidget* key_heading = gtk_label_new(nullptr);
    gtk_label_set_markup(GTK_LABEL(key_heading), "<b>Signing key</b>");
    gtk_label_set_xalign(GTK_LABEL(key_heading), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), key_heading, FALSE, FALSE, 0);

    st->key_generate_radio =
        gtk_radio_button_new_with_label(nullptr, "Generate a new key");
    st->key_existing_radio = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(st->key_generate_radio), "Use an existing key file");
    g_signal_connect(st->key_generate_radio, "toggled",
                     G_CALLBACK(on_key_mode_toggled), st);
    g_signal_connect(st->key_existing_radio, "toggled",
                     G_CALLBACK(on_key_mode_toggled), st);

    st->generated_key_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(st->generated_key_entry),
        "New key file path (default: next to the output as <id>.key.json)");
    st->existing_key_chooser = gtk_file_chooser_button_new(
        "Select an existing key file", GTK_FILE_CHOOSER_ACTION_OPEN);

    GtkWidget* key_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(key_grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(key_grid), 10);
    gtk_grid_attach(GTK_GRID(key_grid), st->key_generate_radio, 0, 0, 1, 1);
    gtk_widget_set_hexpand(st->generated_key_entry, TRUE);
    gtk_grid_attach(GTK_GRID(key_grid), st->generated_key_entry, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(key_grid), st->key_existing_radio, 0, 1, 1, 1);
    gtk_widget_set_hexpand(st->existing_key_chooser, TRUE);
    gtk_grid_attach(GTK_GRID(key_grid), st->existing_key_chooser, 1, 1, 1, 1);
    gtk_box_pack_start(GTK_BOX(box), key_grid, FALSE, FALSE, 0);

    // Output.
    GtkWidget* out_grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(out_grid), 10);
    st->output_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(st->output_entry),
                                   "Output .lexe path (default: $HOME/<id>.lexe)");
    grid_add_row(out_grid, 0, "Output file:", st->output_entry);
    gtk_box_pack_start(GTK_BOX(box), out_grid, FALSE, FALSE, 0);

    // Build button.
    GtkWidget* buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(buttons, GTK_ALIGN_END);
    GtkWidget* close_button = gtk_button_new_with_label("Close");
    g_signal_connect(close_button, "clicked", G_CALLBACK(on_close_clicked),
                     nullptr);
    st->build_button = gtk_button_new_with_label("Build .lexe");
    g_signal_connect(st->build_button, "clicked", G_CALLBACK(on_build_clicked),
                     st);
    gtk_box_pack_start(GTK_BOX(buttons), close_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(buttons), st->build_button, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(box), buttons, FALSE, FALSE, 0);

    // Match the initial radio selection.
    on_key_mode_toggled(nullptr, st);
    return box;
}

GtkWidget* build_progress_page(BuilderState* st) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 24);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);

    st->spinner = gtk_spinner_new();
    gtk_widget_set_size_request(st->spinner, 48, 48);
    gtk_widget_set_halign(st->spinner, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->spinner, FALSE, FALSE, 0);

    st->progress_label = gtk_label_new("Building and signing your package…");
    gtk_widget_set_halign(st->progress_label, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->progress_label, FALSE, FALSE, 0);

    return box;
}

GtkWidget* build_result_page(BuilderState* st) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);

    GtkWidget* heading = gtk_label_new(nullptr);
    gtk_label_set_markup(
        GTK_LABEL(heading),
        "<span size=\"large\" weight=\"bold\" foreground=\"#1a7f37\">Build "
        "succeeded</span>");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);

    st->result_status_label = add_result_label(box, false);
    st->result_path_label = add_result_label(box, true);
    st->result_verify_label = add_result_label(box, false);
    st->result_pubkey_label = add_result_label(box, true);
    st->result_keynote_label = add_result_label(box, true);

    GtkWidget* buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(buttons, GTK_ALIGN_END);
    GtkWidget* again_button = gtk_button_new_with_label("Build another");
    g_signal_connect(again_button, "clicked",
                     G_CALLBACK(on_build_another_clicked), st);
    GtkWidget* close_button = gtk_button_new_with_label("Close");
    g_signal_connect(close_button, "clicked", G_CALLBACK(on_close_clicked),
                     nullptr);
    gtk_box_pack_start(GTK_BOX(buttons), again_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(buttons), close_button, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(box), buttons, FALSE, FALSE, 0);

    return box;
}

void build_ui(BuilderState* st) {
    st->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(st->window), "Lexe Builder");
    gtk_window_set_default_size(GTK_WINDOW(st->window), 620, 720);
    g_signal_connect(st->window, "destroy", G_CALLBACK(on_window_destroy),
                     nullptr);

    st->stack = gtk_stack_new();

    GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroller), build_form_page(st));

    gtk_stack_add_named(GTK_STACK(st->stack), scroller, "form");
    gtk_stack_add_named(GTK_STACK(st->stack), build_progress_page(st),
                        "progress");

    GtkWidget* result_scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(result_scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(result_scroller), build_result_page(st));
    gtk_stack_add_named(GTK_STACK(st->stack), result_scroller, "result");

    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "form");
    gtk_container_add(GTK_CONTAINER(st->window), st->stack);
}

} // namespace

int main(int argc, char** argv) {
    gtk_init(&argc, &argv);

    // Deliberately not freed: worker threads may still reference the state when
    // the main loop quits, and the process is exiting anyway.
    BuilderState* st = new BuilderState();
    build_ui(st);
    gtk_widget_show_all(st->window);
    // The generated-key note is hidden until a key is actually generated.
    gtk_widget_hide(st->result_keynote_label);
    gtk_main();
    return 0;
}

#endif // !LEXE_GUI_VIEWMODEL_ONLY
