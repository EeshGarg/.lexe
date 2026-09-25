#pragma once
// diagnostics — structured execution-error records (Definitive Architecture
// §9). Every hard boolean gate in the install/run flow follows one rule:
//
//     any ? bool failed --> .lexe-error message
//
// and a ".lexe-error message" here is a TYPED RECORD, never an arbitrary
// string. A record names the application, the stage that failed, the execution
// chain that was attempted, the host OS/ISA, the runtime version, the exit
// code or signal, references to captured stdout/stderr, and a timestamp — so a
// real failure is always distinguishable from a successful-but-invisible run
// (the alpha's "console Hello World looked like a failed launch").
//
//     <state>/errors/<application-id>/<timestamp>-<n>.json      the record
//     <state>/errors/<application-id>/<timestamp>-<n>.stdout    captured output
//     <state>/errors/<application-id>/<timestamp>-<n>.stderr
//
// The store is SIZE-LIMITED in both directions: each captured stream is
// truncated, and old records are pruned, so a broken application cannot
// generate unlimited diagnostic data (§9).

#include "core/paths.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace lexe {

/// Where in the definitive install+run flow the failure happened (§7). The
/// stage is typed so a frontend can explain it without parsing message text.
enum class FailureStage {
    Verification,      // .LEXE VERIFIER: hashes/signature/structure/role
    ExecutionPolicy,   // READ EXECUTION POLICY: mission-critical refusal
    ChainResolution,   // SELECT BEST ALLOWED EXECUTION CHAIN: none available
    RuntimeResolution, // RUNTIME RESOLUTION: dependencies/runtime unsatisfied
    Integration,       // desktop/MIME/launch-reference registration
    Compile,           // HOST-ISA COMPILE: a portable package failed to build
    Install,           // extraction/promotion of the application store
    Isolation,         // SANDBOX / PREPARE could not be established
    Launch,            // exec itself failed (missing/unrunnable entrypoint)
    Runtime,           // the application started and then failed/crashed
};
const char* to_string(FailureStage s);
bool failure_stage_from_string(const std::string& text, FailureStage& out);

/// One structured error record (§9).
struct ErrorRecord {
    std::string schema = "lexe.error/1";
    std::string application_id;
    std::string application_version;  // "" when not resolved yet
    FailureStage stage = FailureStage::Runtime;
    std::string summary;              // one-line, human-first
    std::string detail;               // the full explanation
    std::string execution_chain;      // e.g. "native", "proton+fex"
    std::string host_os;              // e.g. "Linux 6.x (Fedora 44)"
    std::string host_isa;             // "x86_64" / "aarch64"
    std::string runtime_version;      // lexe runtime version string
    std::string runtime_profile;      // resolved runtime/dependency profile
    std::optional<int> exit_code;     // set when the child exited normally
    std::optional<int> signal;        // set when the child was killed
    std::string launch_mode;          // declared gui/console/service
    std::string timestamp;            // RFC 3339 UTC

    // Filled in by ErrorStore::record(): absolute paths of captured streams.
    std::string stdout_path;
    std::string stderr_path;
    /// Absolute path of the record file itself — this is what "Copy Error
    /// Path" copies (§9).
    std::string record_path;

    std::string to_json() const;
    static ErrorRecord from_json(std::string_view text);

    /// The multi-line "Copy Error Details" text shown by the error view (§9).
    std::string to_details_text() const;
};

/// Bounded append-only store of error records for one user (§9).
class ErrorStore {
public:
    explicit ErrorStore(const Paths& paths);

    /// Cap on a single captured stream (bytes kept; the tail is kept because
    /// the end of the output is where the failure is).
    static constexpr std::size_t kMaxStreamBytes = 64u * 1024u;
    /// Cap on retained records per application; the oldest are pruned first.
    static constexpr std::size_t kMaxRecordsPerApp = 50;

    /// `<state>/errors/<id>` — the directory "Open Error Folder" opens (§9).
    std::filesystem::path app_dir(const std::string& id) const;

    /// Write `record` (and the optional captured streams, truncated to
    /// kMaxStreamBytes) into the store, prune old records, and return the
    /// stored record with record_path/stdout_path/stderr_path filled in.
    /// Never throws for a filesystem problem: diagnostics must not be able to
    /// turn a recoverable failure into a second failure. A best-effort store
    /// returns a record with an empty record_path.
    ErrorRecord record(ErrorRecord record,
                       const std::string& captured_stdout = {},
                       const std::string& captured_stderr = {}) const;

    /// Most recent records for `id`, newest first (at most `limit`).
    std::vector<ErrorRecord> history(const std::string& id,
                                     std::size_t limit = 20) const;

    /// The most recent record for `id`, if any.
    std::optional<ErrorRecord> latest(const std::string& id) const;

    /// Delete every record for `id`. Returns how many were removed.
    std::size_t clear(const std::string& id) const;

    /// Application ids that currently have at least one record.
    std::vector<std::string> applications_with_errors() const;

private:
    Paths paths_;
};

/// A record with the fields every hard gate fills the same way (application,
/// version, stage, summary, detail) plus the ones that describe THIS machine
/// and runtime. Callers add only what is specific to their failure.
ErrorRecord make_error_record(const std::string& id, const std::string& version,
                              FailureStage stage, const std::string& summary,
                              const std::string& detail);

/// Record `record`, then throw `Ex` with `message` and the record's path
/// appended. A hard gate always produces BOTH a typed failure and a
/// `.lexe-error` record — §9's "any ? bool failed --> .lexe-error message" —
/// and this is the one place that pairing is implemented.
template <typename Ex>
[[noreturn]] void fail_with_record(const Paths& paths, ErrorRecord record,
                                   const std::string& message,
                                   const std::string& captured_stdout = {},
                                   const std::string& captured_stderr = {}) {
    record = ErrorStore(paths).record(std::move(record), captured_stdout,
                                      captured_stderr);
    std::string full = message;
    if (!record.record_path.empty()) {
        full += "\n  diagnostic: " + record.record_path;
    }
    throw Ex(full);
}

/// A best-effort host-OS description for a record ("Linux 6.16.7 (Fedora 44)").
std::string host_os_description();

} // namespace lexe
