#pragma once
// hostbuild — host-ISA compilation of a portable package (Definitive
// Architecture §5 and §7, FORMAT-0.1 §5.8 and §6.9).
//
//         SAME App.lexe
//               |
//     +---------+---------+
//     |         |         |
//   x86-64    ARM64    RISC-V
//     |         |         |
//   compile  compile  compile      <- on the destination machine
//     |         |         |
//     +---------+---------+
//               |
//         Native Linux
//
// The architecture attaches four properties to that arrow, and this module
// exists to hold all four in one place:
//
//   1. APPROVAL gates the OPERATION. Nothing compiles because a package asked
//      to; something compiles because the owner of the installation said so,
//      for this package and this version, and the decision is recorded.
//   2. The build runs UNPRIVILEGED and ISOLATED. It is the launch sandbox with
//      a writable build tree, the network denied unconditionally and no
//      display — not a shell-out, and not a privileged one.
//   3. The OUTPUT IS VERIFIED as a host-ISA native executable before anything
//      uses it. A build that "succeeded" and produced a shell script, an
//      archive, a foreign-ISA binary or nothing at all is a failed install.
//   4. Approval authorizes the operation; it grants NO privilege. Build code
//      gets strictly less authority than the installed application would.
//
// The output of a build is not covered by the package's signed `hashes.json`
// — it did not exist when the package was signed. It is recorded here instead,
// in a per-version `build.json`, so tamper detection, `lexe doctor` and repair
// treat a compiled entrypoint exactly as they treat an extracted one.

#include "lexe/package/manifest.hpp"
#include "lexe/base/paths.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace lexe {

/// One host executable a build recipe named, and whether this machine has it.
struct ToolchainEntry {
    std::string name; // as declared in build.toolchain
    std::string path; // absolute path when present, "" when missing
    bool present = false;
};

/// The result of checking this host against `build.toolchain`. Produced BEFORE
/// approval is sought, so the answer to "can this machine build this package?"
/// never depends on having started a build.
struct ToolchainReport {
    bool complete = false; // every declared tool was found
    std::vector<ToolchainEntry> entries;
    std::vector<std::string> missing;
    /// One ready-to-print sentence: what is missing, or what was found.
    std::string summary;
};

ToolchainReport probe_toolchain(const BuildRecipe& recipe);

/// The exact argv a recipe runs, resolved from `build.system`. Pure: the same
/// manifest always yields the same argv, so what a build will do is inspectable
/// (and testable) without running anything.
///
/// `make`  -> make -C <sourceDir> (the driver the runtime invokes itself)
/// `cmake` -> a configure+build pair, returned in order
/// `command` -> exactly the manifest's argv, once
std::vector<std::vector<std::string>> build_commands(const Manifest& manifest);

/// Who approved compiling this package, and when (property 1).
///
/// There is no privileged "administrator" in a per-user installation, and
/// pretending otherwise would be the kind of claim this codebase does not
/// make. `authority` records what the approval actually was: "user" for an
/// install into the invoking user's own home — which is the only install scope
/// 0.1 supports — so a later reader can tell an owner's decision from a
/// system-wide one if system scope ever exists.
struct CompileApproval {
    bool granted = false;
    std::string authority = "user";
    std::string approved_by; // the OS user name, "" when unavailable
    std::string approved_at; // RFC 3339 UTC

    /// An approval given now, by whoever is running this process. Default-
    /// constructed means NOT approved, so nothing compiles by omission.
    static CompileApproval grant();
};

/// The record written to `<meta>/<version>/build.json`.
struct BuildRecord {
    std::string schema = "lexe.build/1";
    std::string application_id;
    std::string application_version;
    std::string build_system;     // "make" / "cmake" / "command"
    std::string source_dir;
    std::string host_isa;         // the ISA the output was verified against
    std::string built_at;         // RFC 3339 UTC
    std::string runtime_version;
    CompileApproval approval;
    std::vector<ToolchainEntry> toolchain;
    /// SHA-256 of every file the build produced, keyed exactly like
    /// `hashes.json` ("payload/bin/app"), so one lookup answers "what should
    /// this file hash to?" for native and portable installs alike.
    std::map<std::string, std::string> products;

    std::string to_json() const;
    static BuildRecord from_json(std::string_view text);
    /// Load `<meta_dir>/build.json`, or nullopt when there is none (which is
    /// the normal case for a native package).
    static std::optional<BuildRecord> load(const std::filesystem::path& meta_dir);
    void save(const std::filesystem::path& meta_dir) const;
};

/// Everything a compile needs. `build_tree` is the STAGED version directory:
/// the build runs inside it, before promotion, so a failed build never
/// replaces a working installation.
struct CompileRequest {
    Manifest manifest;
    std::filesystem::path build_tree;
    std::filesystem::path scratch_dir; // private writable HOME/cache for the build
    CompileApproval approval;
};

/// Which gate a compile stopped at. The caller maps this to an exception type
/// (and therefore a CLI exit code), because "you did not approve this" and
/// "this machine cannot build it" are different answers to the user and must
/// not be flattened into one.
enum class CompileOutcome {
    Built,             // the output exists and is a verified host-ISA ELF
    NotApproved,       // no ADMIN COMPILE APPROVAL  -> PermissionError
    ToolchainMissing,  // the host lacks a declared tool -> CompileError
    NoSandbox,         // no isolated build environment  -> IsolationError
    BuildFailed,       // a build command exited nonzero -> CompileError
    OutputNotAccepted, // missing / not an ELF / wrong ISA -> CompileError
};
const char* to_string(CompileOutcome o);

/// What a compile did. Returned whether or not it succeeded, so the caller can
/// put the build's OWN output into the structured error record — a failed
/// compile without the compiler's diagnostics is not a diagnosis.
struct CompileResult {
    bool ok = false;
    CompileOutcome outcome = CompileOutcome::NotApproved;
    BuildRecord record;
    std::string stdout_text;
    std::string stderr_text;
    std::vector<std::string> commands_run; // rendered argv, in order
    std::string failure;                   // "" when ok
    std::string hint;                      // the actionable next step, if any
};

/// Compile a portable package's payload for this host, inside the sandbox.
///
/// Never throws for a build outcome — the result says what happened. It never
/// builds unconfined, never proceeds without approval, and never accepts an
/// output it has not verified as a host-ISA native executable.
CompileResult compile_for_host(const Paths& paths, const CompileRequest& req);

/// The name of the record file inside a version's meta directory.
inline constexpr const char* kBuildRecordFile = "build.json";

} // namespace lexe
