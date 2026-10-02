#pragma once
// util — foundation helpers shared by every module (ARCHITECTURE.md #Modules).
// Encoding (hex, RFC 4648 base64 with padding — used by FORMAT-0.1 §3/§4),
// file slurp/spit, recursive directory operations, environment access,
// shell-free process spawning (security invariant #3), RFC 3339 timestamps.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lexe::util {

// --- hex (lowercase; FORMAT-0.1 §3 digests) ---
std::string hex_encode(const std::uint8_t* data, std::size_t len);
std::string hex_encode(const std::vector<std::uint8_t>& data);
/// Strict decode: even length, [0-9a-fA-F] only. Throws lexe::Error.
std::vector<std::uint8_t> hex_decode(std::string_view hex);

// --- base64 (RFC 4648 standard alphabet, WITH padding; FORMAT-0.1 §4) ---
std::string base64_encode(const std::uint8_t* data, std::size_t len);
std::string base64_encode(const std::vector<std::uint8_t>& data);
/// Strict decode: length % 4 == 0, correct '=' padding, no whitespace.
/// Throws lexe::Error on malformed input.
std::vector<std::uint8_t> base64_decode(std::string_view b64);

// --- whole-file IO ---
/// Read a file's bytes. Throws NotFoundError if missing, Error on IO failure.
std::vector<std::uint8_t> slurp(const std::filesystem::path& file);
/// Read a file as text (bytes taken verbatim, no newline translation).
std::string slurp_text(const std::filesystem::path& file);
/// Write bytes to a file (binary, truncate). Creates parent directories.
void spit(const std::filesystem::path& file, const std::uint8_t* data, std::size_t len);
void spit(const std::filesystem::path& file, const std::vector<std::uint8_t>& data);
void spit(const std::filesystem::path& file, std::string_view text);
/// Write `text` to `file` atomically: a sibling temp file then rename over the
/// destination, so a crash never leaves a half-written file (falls back to
/// remove+rename where rename-over-existing is unsupported). Creates parents.
void write_atomic(const std::filesystem::path& file, std::string_view text);

// --- directory operations ---
/// Recursively copy `from` (file or directory) to `to`, overwriting.
void copy_recursive(const std::filesystem::path& from, const std::filesystem::path& to);
/// Recursively delete; missing paths are not an error.
void remove_recursive(const std::filesystem::path& p);

// --- text ---
/// Whether `text` is well-formed UTF-8 (RFC 3629).
///
/// Strict on purpose, and each rejection is a real attack shape rather than
/// pedantry: an OVERLONG encoding lets the same character be written more than
/// one way, so a name that compares unequal to `..` can decode to it; a
/// SURROGATE half (U+D800-DFFF) is not a character and round-trips differently
/// through every UTF-16 platform; and a value above U+10FFFF is not Unicode at
/// all. A validator that accepted any of the three would let two distinct byte
/// strings mean one filename.
///
/// Used for text that becomes a filesystem path, where "we assumed it was UTF-8"
/// is not a safe assumption to leave unchecked.
bool is_valid_utf8(std::string_view text);

// --- this program ---
/// The absolute path of the currently running executable.
///
/// Needed wherever a generated artifact must INVOKE the runtime rather than
/// merely name it. A `.desktop` entry can say bare `lexe` because a desktop
/// session runs it with the user's PATH; a `systemd --user` unit cannot, because
/// it does not inherit one -- an `ExecStart=lexe` unit fails with status 203
/// (EXEC) on a host where the runtime is anywhere but a default PATH entry.
///
/// Read from the kernel (`/proc/self/exe`, `GetModuleFileNameW`) rather than
/// from `argv[0]`, which a caller controls and which is a bare word for anything
/// found on PATH. Returns nullopt when the kernel cannot say -- a container
/// without /proc, most plausibly -- so callers can report the reason instead of
/// generating a unit that cannot start.
std::optional<std::filesystem::path> self_executable();

// --- environment ---
std::optional<std::string> get_env(const std::string& name);
void set_env(const std::string& name, const std::string& value);
void unset_env(const std::string& name);

// --- display ---
/// `text` made safe to put on a terminal as ONE line of human output. Package
/// content (a name, a publisher, an ELF's DT_NEEDED) is publisher-controlled;
/// printed raw, a newline in it forges whole lines ("Verification: PASSED"
/// under the Name row) and an ESC sequence rewrites the screen. Escaped, not
/// dropped, so what the package really says stays visible:
///   C0 controls, DEL       -> \xNN       (newline and tab included)
///   C1 controls             -> \u{NNNN}
///   bidi / invisible format -> \u{NNNN}  (U+061C, 200B-200F, 2028-2029,
///                              202A-202E, 2060-2069, FEFF, FFF9-FFFB)
///   invalid UTF-8 bytes     -> \xNN
/// Everything else, including all other non-ASCII text, passes unchanged.
std::string display_safe(std::string_view text);

// --- temporary directories ---
/// A fresh directory under the system temp directory that nobody else could
/// have named or created first: unpredictable, created exclusively, 0700 on
/// POSIX. Never derive a temp path from package content -- a name the package
/// author can compute is a name another local user can plant.
std::filesystem::path make_private_temp_dir(const std::string& prefix);

// --- processes ---
// No shell anywhere: argv arrays only (ARCHITECTURE.md security invariant #3).
// Implemented with CreateProcessW (correct CommandLineToArgvW-style quoting)
// on Windows and posix_spawnp on POSIX.
struct ProcessResult {
    int exit_code = -1;
    std::string stdout_text; // captured child stdout (empty when not captured)
    std::string stderr_text; // captured child stderr (empty when not captured)
    /// The signal that killed the child, when it was killed rather than
    /// exiting. Diagnostics must distinguish "exited 1" from "killed by
    /// SIGSEGV" (Definitive Architecture §9).
    std::optional<int> signal;
    /// Total bytes the child wrote to each stream, which is NOT the size of the
    /// strings above when `max_retained_bytes` capped them. Recorded so a
    /// diagnostic can say "first 256 KiB of 8 MiB" rather than presenting a
    /// sample as the whole thing — a truncation nobody is told about is just a
    /// quieter version of losing the output.
    std::uint64_t stdout_total_bytes = 0;
    std::uint64_t stderr_total_bytes = 0;
    bool stdout_truncated = false;
    bool stderr_truncated = false;
};
struct RunOptions {
    std::optional<std::filesystem::path> cwd; // child working directory
    bool capture_stdout = true; // false: child inherits our stdout (launcher)
    bool capture_stderr = false; // false: child inherits our stderr

    /// Write captured bytes THROUGH to these streams as they arrive, rather than
    /// only returning them at the end. Null (the default) keeps the old
    /// collect-then-return behaviour.
    ///
    /// This is how a launcher relays a program's output without holding it.
    /// Capturing and then relaying at exit meant the launcher's memory grew with
    /// the program's output — measured at roughly twice its size, so 512 MiB of
    /// output cost about 1 GB of RSS while the program itself used 1.5 MB. A
    /// program that legitimately streams (an archiver, a dump, a transcode) took
    /// the launcher down with it, and a hostile package could exhaust the
    /// session deliberately.
    ///
    /// It also changes WHEN output appears, which is a fix in itself: a
    /// long-running program's output now arrives as it is produced instead of
    /// being withheld until exit.
    std::FILE* tee_stdout = nullptr;
    std::FILE* tee_stderr = nullptr;

    /// Cap on how much of each stream is RETAINED in the result. 0 means no cap.
    ///
    /// Retention exists for diagnostics — an error record carries the output of
    /// a failed run — and diagnostics do not need gigabytes. With a tee set, the
    /// caller has already had every byte, so the retained copy is a sample and
    /// the cap is what makes the memory bounded. It also stops a multi-hundred-
    /// megabyte error record being written to disk, which was the same bug
    /// wearing a different hat.
    std::size_t max_retained_bytes = 0;
};
/// Spawn argv[0] (searched on PATH) with argv[1..] as arguments, wait for
/// exit. stderr is inherited. Throws Error if the process cannot be started.
ProcessResult run_process(const std::vector<std::string>& argv,
                          const RunOptions& opts = {});

/// Options for spawn_detached().
///
/// The detached process gets **fresh stdio**: stdin, stdout and stderr are all
/// reopened on `/dev/null` before it starts. That is not tidiness, it is the
/// difference between returning and appearing to hang.
///
/// A detached child inherits the caller's descriptors, so when the caller's
/// stdout is a PIPE the pipe stays open for as long as the child lives -- which
/// for a service is forever. The process returned; the observable effect did
/// not. Measured:
///
///   stdout to a file          rc=0 in 30 ms, payload survives
///   stdout to a pipe          never returned (30 s timeout, 2/2)
///   OUT=$(lexe run svc)       never returned (30 s timeout, 2/2)
///
/// So `OUT=$(lexe run svc)`, `lexe run svc | tee log`, and every script, CI job,
/// GUI or supervisor that captures output hung, while the same command with
/// stdout redirected to a file returned in 30 ms. FORMAT-0.1 §5.6 says the
/// runtime RETURNS once a service is running; for any consumer that is not a
/// terminal or a file, it did not.
///
/// `/dev/null` rather than a log file, deliberately. §5.6 establishes that a
/// detached direct run is unsupervised and has no status to report, so
/// discarding its output is consistent rather than a loss -- and inventing a log
/// file here would invent unbounded state with it, which is a defect this
/// project has already had to fix once (`locks/` grew without limit). The
/// supported way to capture a service's output is session management, where
/// systemd gives the unit the journal.
struct DetachOptions {
    std::optional<std::filesystem::path> cwd;
    /// A lock file the SUPERVISOR should hold (shared) for as long as the
    /// detached process runs, or empty for none.
    ///
    /// A detached launch outlives the process that started it, so a lease held
    /// by the starter is released the moment it returns — and the files the
    /// detached application is running from could then be removed underneath
    /// it. The supervisor opens its OWN descriptor on this file, so the
    /// starter releasing its lease does not release the supervisor's: flock
    /// locks belong to the open file description, and a descriptor merely
    /// inherited across fork shares the starter's.
    std::filesystem::path supervisor_lock_file;
};

/// Start `argv` so that it outlives this process.
///
/// Double-forks: this process waits only for an intermediate that exits at
/// once, so no zombie is left behind, and the surviving SUPERVISOR is
/// reparented to init. The supervisor takes `supervisor_lock_file`, starts the
/// real process in its own session, waits for it, and exits — which is the
/// whole of what "service mode" means here. It is not a session-manager
/// service: nothing restarts it, nothing starts it at boot, and nothing will
/// report its status but `.LEXE`.
///
/// Throws Error when the process cannot be started. POSIX only; on Windows it
/// throws, because a platform without the isolation backend has no detached
/// launch to offer either.
void spawn_detached(const std::vector<std::string>& argv,
                    const DetachOptions& opts = {});

// --- time ---
/// Current UTC time as RFC 3339, e.g. "2026-07-13T12:34:56Z".
std::string now_utc_string();

/// Search `PATH` for the executable `name` and return its absolute path, or
/// "" when it is not there. A `name` containing a '/' is treated as a path and
/// only checked for existence. Never executes anything: probing what a host
/// has must be cheap and free of side effects.
/// Find `name` on PATH.
///
/// `skip_foreign_mounts` drops PATH entries under `/mnt/`, where a Linux host
/// mounts a foreign OS's filesystem. It exists for a measured reason and the
/// same one twice over.
///
/// On a WSL host the inherited PATH carries the whole Windows PATH -- around
/// thirty-six directories on a DrvFS mount where a single failed stat costs
/// roughly 4 ms -- so a lookup that MISSES walks all of them. Provider discovery
/// asks for several candidates across several providers, so the misses multiply:
/// `lexe doctor` was measured at 3466 ms against 22 ms with a clean PATH, and
/// `lexe runtime list` at 2239 ms against 6 ms. 734 `newfstatat` calls, 576 of
/// them under /mnt/c, accounted for 2.2 s of a 2.5 s command.
///
/// Nothing was wrong with the search except where it was looking. A Windows
/// executable cannot be a Linux compatibility provider or a Linux build tool, so
/// those directories can never hold an answer and the cost buys nothing. Left
/// off by default, where PATH means what the caller says it means.
///
/// This is the second instance of the identical defect -- the first was the
/// launcher hunting terminal emulators across the same directories, at 1634 ms
/// in 511 stats. Any lookup that expects to MISS on a WSL host should pass true.
std::string find_on_path(const std::string& name,
                         bool skip_foreign_mounts = false);

} // namespace lexe::util
