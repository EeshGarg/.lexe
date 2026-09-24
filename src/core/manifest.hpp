#pragma once
// manifest — the `lexe.json` application manifest (FORMAT-0.1 §5). A plain
// value struct plus strict parse/serialize. Unknown JSON fields are ignored
// (forward compatibility); missing/invalid REQUIRED fields are rejected.

#include "core/crypto.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace lexe {

/// What a `.lexe` artifact IS (Definitive Architecture §15.1 "Role
/// distinction"). Install and launch artifacts share the `.lexe` container and
/// MIME type; the SIGNED manifest is what tells the handler which operation to
/// perform, so the role can never be changed by renaming a file.
enum class PackageRole {
    Application, // an installable application package (App.lexe / install.lexe)
    Launch,      // a launch reference to an already-installed app (run.lexe)
};
const char* to_string(PackageRole r);

/// How an application presents itself when it is launched (Definitive
/// Architecture §14.4). Presentation is DECLARED, never inferred from whether
/// the desktop happened to show a terminal.
enum class LaunchMode {
    Gui,     // opens its own window; no terminal is provided
    Console, // needs a visible console when launched from the desktop
    Service, // background/service; detached, no terminal, no window expected
};
const char* to_string(LaunchMode m);
/// Parse a `launch.mode` string; returns false for an unrecognised value.
bool launch_mode_from_string(const std::string& text, LaunchMode& out);

/// One `integration.fileAssociations[]` element (FORMAT-0.1 §5 optional).
struct FileAssociation {
    std::string extension; // e.g. ".example"
    std::string mime_type; // e.g. "application/x-example"
};

/// Mirrors FORMAT-0.1 §5. Optional fields carry their documented defaults.
struct Manifest {
    // --- required for every role ---
    std::string lexe_version;         // MUST be "0.1"
    std::string id;                   // reverse-DNS, ≤255 chars
    std::string name;                 // non-empty
    std::string version;              // non-empty, ordered per §8
    std::string publisher_name;       // publisher.name, non-empty
    std::string publisher_public_key; // publisher.publicKey, "ed25519:…" (§4)

    /// `role` (optional, default Application). The handler dispatches on THIS,
    /// not on the file name (Definitive Architecture §15.1).
    PackageRole role = PackageRole::Application;

    // --- role == Launch only ---
    /// `launch.applicationId` — the installed App ID this reference launches.
    std::string launch_application_id;

    // --- role == Application only (required there, absent for Launch) ---
    std::string application_type;     // MUST be "native" in 0.1
    std::vector<std::string> architectures;   // non-empty; x86_64 / aarch64
    std::string entrypoint_executable;        // relative path inside payload/
    std::string install_mode;                 // MUST be "bundled" in 0.1

    // --- execution policy (Definitive Architecture §6, §8) ---
    /// `execution.missionCritical` — an execution RESTRICTION, not a safety
    /// certification: Linux-native + host-ISA-native + verified only. Any
    /// compatibility layer, ISA translation or "run anyway" is forbidden.
    bool mission_critical = false;
    /// `execution.allowedChains` — the execution chains the PUBLISHER permits,
    /// in preference order. Default {"native"}. The resolver may only choose a
    /// chain from this list; the UI only offers chains from this list (§8).
    std::vector<std::string> allowed_chains;

    // --- launch semantics (Definitive Architecture §14.4) ---
    /// `launch.mode` — declared presentation. Default Gui: a launched
    /// application is expected to show its own window, and exit code 0 is
    /// success even when no window appears. A console program MUST declare
    /// "console" so .LEXE can apply a terminal policy instead of looking like
    /// "nothing happened".
    LaunchMode launch_mode = LaunchMode::Gui;
    /// `launch.singleInstance` — advisory hint for frontends.
    bool launch_single_instance = false;

    // --- optional with defaults (§5) ---
    std::vector<std::string> entrypoint_arguments; // default []
    std::string publisher_website;                 // default ""
    std::string install_scope = "user";
    std::uint64_t install_estimated_size = 0;      // 0 = not provided
    std::vector<std::string> permissions;          // informational in 0.1

    // updates (§7); disabled when the block is absent
    bool updates_enabled = false;
    std::string updates_channel = "stable";
    std::string updates_manifest_url;              // https:// (tests: file://)
    bool updates_allow_source_change = true;

    // integration (§9)
    bool integration_desktop_entry = true;
    std::vector<std::string> categories;
    std::vector<FileAssociation> file_associations;

    /// Parse and validate the exact bytes of a stored `lexe.json` entry.
    /// Throws VerificationError describing the first violated §5 constraint.
    static Manifest parse(const std::vector<std::uint8_t>& bytes);
    /// Same, from text (convenience for tools/tests).
    static Manifest parse(std::string_view json_text);

    /// Serialize back to JSON text (used by `lexe pack` tooling and the
    /// registry's manifest.json copy). Not byte-identical to the input.
    std::string to_json() const;

    /// Decode publisher_public_key per FORMAT-0.1 §4 (throws VerificationError).
    crypto::PublicKey decoded_public_key() const;

    /// True when `chain` is permitted by this manifest's execution policy.
    /// Mission-critical packages permit ONLY "native" regardless of the list
    /// (Definitive Architecture §6 FORBID).
    bool chain_allowed(const std::string& chain) const;
    /// The effective, policy-filtered chain list in preference order.
    std::vector<std::string> effective_allowed_chains() const;
};

} // namespace lexe
