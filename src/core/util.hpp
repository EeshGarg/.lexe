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

// --- directory operations ---
/// Recursively copy `from` (file or directory) to `to`, overwriting.
void copy_recursive(const std::filesystem::path& from, const std::filesystem::path& to);
/// Recursively delete; missing paths are not an error.
void remove_recursive(const std::filesystem::path& p);

// --- environment ---
std::optional<std::string> get_env(const std::string& name);
void set_env(const std::string& name, const std::string& value);
void unset_env(const std::string& name);

// --- processes ---
// No shell anywhere: argv arrays only (ARCHITECTURE.md security invariant #3).
// Implemented with CreateProcessW (correct CommandLineToArgvW-style quoting)
// on Windows and posix_spawnp on POSIX.
struct ProcessResult {
    int exit_code = -1;
    std::string stdout_text; // captured child stdout (empty when not captured)
};
struct RunOptions {
    std::optional<std::filesystem::path> cwd; // child working directory
    bool capture_stdout = true; // false: child inherits our stdout (launcher)
};
/// Spawn argv[0] (searched on PATH) with argv[1..] as arguments, wait for
/// exit. stderr is inherited. Throws Error if the process cannot be started.
ProcessResult run_process(const std::vector<std::string>& argv,
                          const RunOptions& opts = {});

// --- time ---
/// Current UTC time as RFC 3339, e.g. "2026-07-13T12:34:56Z".
std::string now_utc_string();

} // namespace lexe::util
