// tux32 — see tux32.hpp. The compiled Core 1 baseline + strict JSON parse.

#include "core/tux32.hpp"

#include "core/error.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>

namespace lexe {

std::string Tux32Profile::glibc_ceiling() const {
    return std::to_string(glibc_major) + "." + std::to_string(glibc_minor);
}

bool Tux32Profile::supports_arch(const std::string& arch) const {
    return std::find(architectures.begin(), architectures.end(), arch) !=
           architectures.end();
}

bool Tux32Profile::within_glibc_ceiling(int major, int minor) const {
    return major < glibc_major || (major == glibc_major && minor <= glibc_minor);
}

const Tux32Profile& tux32_core_1() {
    static const Tux32Profile kProfile = [] {
        Tux32Profile p;
        p.id = "tux32-core-1";
        p.spec_version = "1";
        p.executable_format = "elf-dynamic";
        p.architectures = {"x86_64"};
        p.cpu_baseline = "x86-64-v1";
        p.glibc_major = 2;
        p.glibc_minor = 31;
        p.dynamic_linking =
            "Dynamically linked against the host glibc via the host-provided "
            "loader (ld-linux-x86-64.so.2). Fully static binaries are out of "
            "scope for Core 1 (they do not exercise the dynamic ABI contract).";
        p.kernel_baseline =
            "Linux 5.10 or newer with user namespaces available for the sandbox.";
        p.host_provided =
            "The core system runtime present on every conforming host: glibc "
            "(libc/libm/libdl/libpthread/librt/…), libgcc_s, the dynamic loader, "
            "and the vDSO. Never bundled.";
        p.must_bundle =
            "Every other shared library the application needs, carried in the "
            "payload.";
        p.forbidden =
            "Host GPU/graphics/accelerator driver interfaces (libGL, libEGL, "
            "libcuda, libvulkan, libdrm, …) — provided by the host, never "
            "bundled. A package needing them requires host driver passthrough.";
        p.filesystem =
            "A read-only application image plus private, writable data, cache "
            "and temp roots (FORMAT-0.1 §9). No ambient filesystem access.";
        p.environment =
            "A sanitized environment allow-list; dangerous variables "
            "(LD_PRELOAD, LD_LIBRARY_PATH, …) are stripped.";
        p.isolation =
            "The Linux baseline sandbox (docs/ISOLATION.md): read-only app "
            "image, private data/cache/temp, environment sanitization, and "
            "network denied unless the network permission is granted.";
        p.graphics =
            "Headless/terminal applications only in Core 1. GUI forwarding is "
            "out of scope.";
        p.network =
            "No network unless the application declares and the user approves "
            "the `network` permission; otherwise the network namespace is "
            "unshared (denied and enforced).";
        p.data_paths =
            "Per-App persistent data survives update/rollback; cache is "
            "disposable; temp is per-launch and private.";
        p.claim_language =
            "\"Targets Tux32 Core 1\" / \"Verified against the Core 1 glibc "
            "symbol ceiling\". Core Portable does not mean every arbitrary Linux "
            "binary is portable, and runtime dlopen dependencies may require "
            "explicit declaration.";
        p.conformance =
            "A runtime conforms to Core 1 when it provides the host interface "
            "above with a glibc of at least 2.31, the stated kernel/isolation "
            "capabilities, and runs a conforming package's exact signed artifact "
            "unchanged.";
        return p;
    }();
    return kProfile;
}

bool parse_glibc_version(const std::string& v, int& major, int& minor) {
    const std::size_t dot = v.find('.');
    if (dot == std::string::npos) return false;
    try {
        major = std::stoi(v.substr(0, dot));
        minor = std::stoi(v.substr(dot + 1));
        return major >= 0 && minor >= 0;
    } catch (const std::exception&) {
        return false;
    }
}

namespace {

std::string req_string(const nlohmann::json& obj, const char* key) {
    const auto it = obj.find(key);
    if (it == obj.end() || !it->is_string()) {
        throw VerificationError(std::string("tux32 profile: missing/invalid \"") +
                                key + "\"");
    }
    return it->get<std::string>();
}

} // namespace

Tux32Profile parse_profile_json(std::string_view text) {
    // Strict: duplicate-key rejection + a bounded byte budget.
    const nlohmann::json j =
        json_strict::parse(text, "tux32 profile", limits::kMaxManifestBytes);
    if (!j.is_object()) {
        throw VerificationError("tux32 profile: top-level value is not an object");
    }
    Tux32Profile p;
    p.id = req_string(j, "id");
    p.spec_version = req_string(j, "specVersion");
    p.executable_format = req_string(j, "executableFormat");

    const auto arch = j.find("architectures");
    if (arch == j.end() || !arch->is_array() || arch->empty()) {
        throw VerificationError("tux32 profile: \"architectures\" must be a "
                                "non-empty array");
    }
    for (const auto& a : *arch) {
        if (!a.is_string()) {
            throw VerificationError("tux32 profile: architecture is not a string");
        }
        p.architectures.push_back(a.get<std::string>());
    }
    p.cpu_baseline = req_string(j, "cpuBaseline");

    const std::string ceiling = req_string(j, "glibcCeiling");
    if (!parse_glibc_version(ceiling, p.glibc_major, p.glibc_minor)) {
        throw VerificationError("tux32 profile: invalid \"glibcCeiling\" \"" +
                                ceiling + "\"");
    }

    // Descriptive fields (present in the machine-readable mirror).
    const auto policy = j.find("policy");
    if (policy != j.end() && policy->is_object()) {
        const auto opt = [&](const char* k) -> std::string {
            const auto it = policy->find(k);
            return (it != policy->end() && it->is_string())
                       ? it->get<std::string>()
                       : std::string();
        };
        p.dynamic_linking = opt("dynamicLinking");
        p.kernel_baseline = opt("kernelBaseline");
        p.host_provided = opt("hostProvided");
        p.must_bundle = opt("mustBundle");
        p.forbidden = opt("forbidden");
        p.filesystem = opt("filesystem");
        p.environment = opt("environment");
        p.isolation = opt("isolation");
        p.graphics = opt("graphics");
        p.network = opt("network");
        p.data_paths = opt("dataPaths");
        p.claim_language = opt("claimLanguage");
        p.conformance = opt("conformance");
    }
    return p;
}

} // namespace lexe
