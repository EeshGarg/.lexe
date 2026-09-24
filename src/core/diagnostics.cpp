// diagnostics — see diagnostics.hpp (Definitive Architecture §9).

#include "core/diagnostics.hpp"

#include "core/error.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"
#include "core/version.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <system_error>

#ifndef _WIN32
#include <sys/utsname.h>
#endif

namespace fs = std::filesystem;

namespace lexe {

namespace {

/// A filename-safe form of an RFC 3339 timestamp ("2026-09-24T18:55:01Z" ->
/// "20260924T185501Z"): sortable lexicographically, no path-hostile bytes.
std::string compact_timestamp(const std::string& rfc3339) {
    std::string out;
    out.reserve(rfc3339.size());
    for (const char c : rfc3339) {
        if (c != '-' && c != ':') out += c;
    }
    if (out.empty()) out = "unknown";
    return out;
}

/// Keep the TAIL of an over-long stream: the end of the output is where the
/// failure is, and a truncation marker keeps the record honest (§9 "logs
/// should be size-limited").
std::string clamp_stream(const std::string& text, std::size_t limit) {
    if (text.size() <= limit) return text;
    const std::string marker =
        "[... " + std::to_string(text.size() - limit) +
        " earlier bytes dropped by the .LEXE diagnostic size limit ...]\n";
    return marker + text.substr(text.size() - limit);
}

/// Record stems ("20260924T185501Z-0") present for an app, sorted oldest first.
std::vector<std::string> record_stems(const fs::path& dir) {
    std::vector<std::string> stems;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return stems;
    for (const fs::directory_entry& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        const fs::path& p = entry.path();
        if (p.extension() != ".json") continue;
        stems.push_back(p.stem().string());
    }
    std::sort(stems.begin(), stems.end());
    return stems;
}

} // namespace

const char* to_string(FailureStage s) {
    switch (s) {
    case FailureStage::Verification: return "verification";
    case FailureStage::ExecutionPolicy: return "execution-policy";
    case FailureStage::ChainResolution: return "chain-resolution";
    case FailureStage::RuntimeResolution: return "runtime-resolution";
    case FailureStage::Integration: return "integration";
    case FailureStage::Install: return "install";
    case FailureStage::Isolation: return "isolation";
    case FailureStage::Launch: return "launch";
    case FailureStage::Runtime: return "runtime";
    }
    return "runtime";
}

bool failure_stage_from_string(const std::string& text, FailureStage& out) {
    static const struct {
        const char* name;
        FailureStage stage;
    } kStages[] = {
        {"verification", FailureStage::Verification},
        {"execution-policy", FailureStage::ExecutionPolicy},
        {"chain-resolution", FailureStage::ChainResolution},
        {"runtime-resolution", FailureStage::RuntimeResolution},
        {"integration", FailureStage::Integration},
        {"install", FailureStage::Install},
        {"isolation", FailureStage::Isolation},
        {"launch", FailureStage::Launch},
        {"runtime", FailureStage::Runtime},
    };
    for (const auto& s : kStages) {
        if (text == s.name) {
            out = s.stage;
            return true;
        }
    }
    return false;
}

std::string host_os_description() {
#ifdef _WIN32
    return "Windows";
#else
    std::string description = "Linux";
    struct utsname info {};
    if (uname(&info) == 0) {
        description = std::string(info.sysname) + " " + info.release;
    }
    // Fedora/Debian/Arch all ship os-release; a distribution name makes a
    // record far more useful when it is pasted into a bug report.
    std::error_code ec;
    for (const char* candidate :
         {"/etc/os-release", "/usr/lib/os-release"}) {
        if (!fs::is_regular_file(candidate, ec)) continue;
        std::ifstream in(candidate);
        std::string line;
        while (std::getline(in, line)) {
            constexpr std::string_view kKey = "PRETTY_NAME=";
            if (line.rfind(kKey.data(), 0) != 0) continue;
            std::string value = line.substr(kKey.size());
            if (value.size() >= 2 && value.front() == '"' &&
                value.back() == '"') {
                value = value.substr(1, value.size() - 2);
            }
            if (!value.empty()) description += " (" + value + ")";
            return description;
        }
        break;
    }
    return description;
#endif
}

std::string ErrorRecord::to_json() const {
    nlohmann::ordered_json j;
    j["schema"] = schema;
    j["timestamp"] = timestamp;
    j["applicationId"] = application_id;
    j["applicationVersion"] = application_version;
    j["stage"] = to_string(stage);
    j["summary"] = summary;
    j["detail"] = detail;
    j["executionChain"] = execution_chain;
    j["launchMode"] = launch_mode;

    nlohmann::ordered_json host;
    host["os"] = host_os;
    host["isa"] = host_isa;
    j["host"] = std::move(host);

    nlohmann::ordered_json runtime;
    runtime["version"] = runtime_version;
    runtime["profile"] = runtime_profile;
    j["runtime"] = std::move(runtime);

    nlohmann::ordered_json outcome;
    if (exit_code.has_value()) outcome["exitCode"] = *exit_code;
    else outcome["exitCode"] = nullptr;
    if (signal.has_value()) outcome["signal"] = *signal;
    else outcome["signal"] = nullptr;
    j["outcome"] = std::move(outcome);

    nlohmann::ordered_json streams;
    streams["stdout"] = stdout_path;
    streams["stderr"] = stderr_path;
    j["streams"] = std::move(streams);

    return j.dump(2) + "\n";
}

ErrorRecord ErrorRecord::from_json(std::string_view text) {
    const nlohmann::json j =
        json_strict::parse(text, "error record", limits::kMaxManifestBytes);
    if (!j.is_object()) {
        throw Error("error record is not a JSON object");
    }
    ErrorRecord r;
    const auto str = [&](const nlohmann::json& parent, const char* key,
                         std::string& out) {
        if (const auto it = parent.find(key);
            it != parent.end() && it->is_string()) {
            out = it->get<std::string>();
        }
    };
    str(j, "schema", r.schema);
    str(j, "timestamp", r.timestamp);
    str(j, "applicationId", r.application_id);
    str(j, "applicationVersion", r.application_version);
    str(j, "summary", r.summary);
    str(j, "detail", r.detail);
    str(j, "executionChain", r.execution_chain);
    str(j, "launchMode", r.launch_mode);
    if (const auto it = j.find("stage"); it != j.end() && it->is_string()) {
        (void)failure_stage_from_string(it->get<std::string>(), r.stage);
    }
    if (const auto host = j.find("host");
        host != j.end() && host->is_object()) {
        str(*host, "os", r.host_os);
        str(*host, "isa", r.host_isa);
    }
    if (const auto rt = j.find("runtime"); rt != j.end() && rt->is_object()) {
        str(*rt, "version", r.runtime_version);
        str(*rt, "profile", r.runtime_profile);
    }
    if (const auto out = j.find("outcome");
        out != j.end() && out->is_object()) {
        if (const auto it = out->find("exitCode");
            it != out->end() && it->is_number_integer()) {
            r.exit_code = it->get<int>();
        }
        if (const auto it = out->find("signal");
            it != out->end() && it->is_number_integer()) {
            r.signal = it->get<int>();
        }
    }
    if (const auto streams = j.find("streams");
        streams != j.end() && streams->is_object()) {
        str(*streams, "stdout", r.stdout_path);
        str(*streams, "stderr", r.stderr_path);
    }
    return r;
}

std::string ErrorRecord::to_details_text() const {
    std::string text;
    const auto line = [&](const char* label, const std::string& value) {
        if (value.empty()) return;
        text += std::string(label) + ": " + value + "\n";
    };
    text += ".LEXE error report\n";
    line("Application", application_id);
    line("Version", application_version);
    line("Stage", to_string(stage));
    line("Summary", summary);
    line("Detail", detail);
    line("Execution chain", execution_chain);
    line("Launch mode", launch_mode);
    line("Host OS", host_os);
    line("Host ISA", host_isa);
    line("Runtime", runtime_version);
    line("Runtime profile", runtime_profile);
    if (exit_code.has_value()) {
        text += "Exit code: " + std::to_string(*exit_code) + "\n";
    }
    if (signal.has_value()) {
        text += "Signal: " + std::to_string(*signal) + "\n";
    }
    line("Timestamp", timestamp);
    line("Record", record_path);
    line("stdout", stdout_path);
    line("stderr", stderr_path);
    return text;
}

ErrorStore::ErrorStore(const Paths& paths) : paths_(paths) {}

fs::path ErrorStore::app_dir(const std::string& id) const {
    validate_app_id(id, "diagnostics");
    return paths_.errors_dir() / id;
}

ErrorRecord ErrorStore::record(ErrorRecord record,
                               const std::string& captured_stdout,
                               const std::string& captured_stderr) const {
    // Diagnostics must never turn a recoverable failure into a second
    // failure: every filesystem problem here degrades to "no record written".
    try {
        if (record.timestamp.empty()) record.timestamp = util::now_utc_string();
        if (record.runtime_version.empty()) {
            record.runtime_version = version::runtime_string();
        }
        if (record.host_isa.empty()) record.host_isa = host_architecture();
        if (record.host_os.empty()) record.host_os = host_os_description();

        const fs::path dir = app_dir(record.application_id);
        std::error_code ec;
        fs::create_directories(dir, ec);
        if (ec) return record;

        // A stable, sortable, collision-free stem even for two failures in the
        // same second.
        const std::string base = compact_timestamp(record.timestamp);
        std::string stem;
        for (int n = 0; n < 1000; ++n) {
            stem = base + "-" + std::to_string(n);
            if (!fs::exists(dir / (stem + ".json"), ec)) break;
        }

        if (!captured_stdout.empty()) {
            const fs::path p = dir / (stem + ".stdout");
            util::spit(p, std::string_view(
                              clamp_stream(captured_stdout, kMaxStreamBytes)));
            record.stdout_path = p.string();
        }
        if (!captured_stderr.empty()) {
            const fs::path p = dir / (stem + ".stderr");
            util::spit(p, std::string_view(
                              clamp_stream(captured_stderr, kMaxStreamBytes)));
            record.stderr_path = p.string();
        }

        const fs::path record_file = dir / (stem + ".json");
        record.record_path = record_file.string();
        util::write_atomic(record_file, record.to_json());

        // Prune oldest-first so a crash loop cannot grow the store without
        // bound (§9).
        std::vector<std::string> stems = record_stems(dir);
        while (stems.size() > kMaxRecordsPerApp) {
            const std::string& oldest = stems.front();
            for (const char* ext : {".json", ".stdout", ".stderr"}) {
                fs::remove(dir / (oldest + ext), ec);
            }
            stems.erase(stems.begin());
        }
    } catch (const std::exception&) {
        record.record_path.clear();
    }
    return record;
}

std::vector<ErrorRecord> ErrorStore::history(const std::string& id,
                                             std::size_t limit) const {
    std::vector<ErrorRecord> out;
    const fs::path dir = app_dir(id);
    std::vector<std::string> stems = record_stems(dir);
    std::reverse(stems.begin(), stems.end()); // newest first
    for (const std::string& stem : stems) {
        if (out.size() >= limit) break;
        const fs::path file = dir / (stem + ".json");
        try {
            ErrorRecord r = ErrorRecord::from_json(util::slurp_text(file));
            r.record_path = file.string();
            out.push_back(std::move(r));
        } catch (const std::exception&) {
            // A corrupt record must not hide the rest of the history.
        }
    }
    return out;
}

std::optional<ErrorRecord> ErrorStore::latest(const std::string& id) const {
    const std::vector<ErrorRecord> recent = history(id, 1);
    if (recent.empty()) return std::nullopt;
    return recent.front();
}

std::size_t ErrorStore::clear(const std::string& id) const {
    const fs::path dir = app_dir(id);
    const std::vector<std::string> stems = record_stems(dir);
    std::error_code ec;
    for (const std::string& stem : stems) {
        for (const char* ext : {".json", ".stdout", ".stderr"}) {
            fs::remove(dir / (stem + ext), ec);
        }
    }
    return stems.size();
}

std::vector<std::string> ErrorStore::applications_with_errors() const {
    std::vector<std::string> ids;
    std::error_code ec;
    const fs::path root = paths_.errors_dir();
    if (!fs::is_directory(root, ec)) return ids;
    for (const fs::directory_entry& entry : fs::directory_iterator(root, ec)) {
        if (!entry.is_directory(ec)) continue;
        const std::string id = entry.path().filename().string();
        if (!app_id_is_valid(id)) continue;
        if (record_stems(entry.path()).empty()) continue;
        ids.push_back(id);
    }
    std::sort(ids.begin(), ids.end());
    return ids;
}

} // namespace lexe
