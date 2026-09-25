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

/// What one layer of an execution chain DOES (FORMAT-0.1 §5.5).
///
/// The vocabulary lives here, beside the manifest, because
/// `execution.allowedChains` is a manifest field and the PARSER has to reason
/// about it — a package whose payload needs a foreign-OS layer while its
/// policy permits none is a contradiction, and contradictions are rejected at
/// parse time rather than discovered at launch. `execpolicy` owns how to find
/// and invoke each layer; it does not own what the names mean.
enum class ChainLayerKind {
    Unknown,        // not a layer this runtime knows
    IsaTranslation, // runs a foreign-ISA Linux binary (FEX, Box64, qemu-user)
    ForeignOs,      // runs a foreign-OS binary (Wine, Proton)
};
const char* to_string(ChainLayerKind k);

/// The kind of a single layer id ("fex", "proton", …).
ChainLayerKind chain_layer_kind(const std::string& layer_id);

/// True when `chain_id` — possibly layered, e.g. "proton+fex" — contains a
/// layer that can run a foreign-OS payload. "native" never can.
bool chain_runs_foreign_os(const std::string& chain_id);

/// What kind of payload an application package carries (FORMAT-0.1 §5.3).
///
/// The difference is not cosmetic: it decides what the `payload-role`
/// verification stage demands of the archive, and whether installing the
/// package compiles anything on this machine.
enum class ApplicationType {
    Native,   // the payload IS the program: a compiled ELF for a declared ISA
    Portable, // the payload is SOURCE, compiled to this host's ISA at install
    Windows,  // the payload is a Windows PE, run through a foreign-OS layer
};
const char* to_string(ApplicationType t);
/// Parse an `applicationType` string; returns false for an unrecognised value.
bool application_type_from_string(const std::string& text,
                                  ApplicationType& out);

/// How a portable package is built (FORMAT-0.1 §5.8 `build`).
///
/// `system` names a build driver the RUNTIME knows how to invoke, so the
/// common cases do not require the publisher to hand over an argv at all.
/// `Command` is the escape hatch for everything else and carries its argv
/// explicitly — as argv, never a shell string, because a shell string is a
/// second language with its own quoting bugs between the manifest and exec.
enum class BuildSystem {
    Make,    // `make` in the source directory
    CMake,   // configure + build out of tree
    Command, // the manifest's own argv
};
const char* to_string(BuildSystem s);
bool build_system_from_string(const std::string& text, BuildSystem& out);

/// The `build` block of a portable package (FORMAT-0.1 §5.8).
struct BuildRecipe {
    BuildSystem system = BuildSystem::Make;
    /// `build.sourceDir` — directory inside `payload/` holding the sources.
    /// The build sees THIS directory and nothing else of the package.
    std::string source_dir;
    /// `build.command` — required for `system: "command"`, forbidden
    /// otherwise. argv[0] is resolved on the sandbox PATH.
    std::vector<std::string> command;
    /// `build.toolchain` — the host executables the build needs. Probed
    /// BEFORE any approval is asked for, so a host that cannot build the
    /// package says so instead of failing halfway through a build.
    std::vector<std::string> toolchain;
};

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
    /// `applicationType` as written, for display and for round-tripping.
    /// `application_kind` is the parsed form; the two never disagree.
    std::string application_type;     // "native" or "portable"
    ApplicationType application_kind = ApplicationType::Native;
    /// The ISAs this package can run on. For `native` that means the
    /// entrypoint ELF targets one of them; for `portable` it means the build
    /// recipe is declared to produce a working program for them. Either way,
    /// the host's ISA must be in this list for the package to install.
    std::vector<std::string> architectures;   // non-empty; x86_64 / aarch64
    /// For `native`, the payload entry that IS the program. For `portable`,
    /// the path (relative to the payload root) the build must PRODUCE — it is
    /// deliberately absent from the archive, and stage 7 rejects a portable
    /// package that ships it.
    std::string entrypoint_executable;        // relative path inside payload/
    std::string install_mode;                 // MUST be "bundled" in 0.1
    /// `build` — present exactly when `applicationType` is `"portable"`.
    BuildRecipe build;

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
    /// The runtime profile the BUILDER targeted ("core-portable",
    /// "forward-runtime", "native-capture"), or "" when the package does not
    /// declare one. Optional and forward-compatible: older runtimes ignore it
    /// (FORMAT-0.1 §5 "unknown fields are ignored").
    ///
    /// Without it every reader re-judged every package against Core Portable,
    /// so a package deliberately built as Native Capture — which is host-locked
    /// BY DEFINITION — was reported as a hard portability FAILURE by the same
    /// runtime whose Builder had just accepted it.
    std::string runtime_profile;

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
