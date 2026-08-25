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

const char* to_string(Core1Verdict v) {
    switch (v) {
    case Core1Verdict::Conformant:              return "conformant";
    case Core1Verdict::ConformantWithNotes:     return "conformant-with-notes";
    case Core1Verdict::SymbolCeilingExceeded:   return "symbol-ceiling-exceeded";
    case Core1Verdict::UnresolvedDependency:    return "unresolved-dependency";
    case Core1Verdict::ForbiddenDependency:     return "forbidden-dependency";
    case Core1Verdict::UnsupportedArchitecture: return "unsupported-architecture";
    case Core1Verdict::UnsupportedExecutable:   return "unsupported-executable";
    case Core1Verdict::InvalidInput:            return "invalid-input";
    case Core1Verdict::IncompleteClosure:       return "incomplete-closure";
    }
    return "invalid-input";
}

namespace {

// The highest GLIBC_x.y requirement in a version-need list. Returns false when
// none is present or parseable.
bool max_glibc_of(const std::vector<std::string>& needs, int& major, int& minor) {
    bool any = false;
    major = -1;
    minor = -1;
    for (const std::string& v : needs) {
        if (v.rfind("GLIBC_", 0) != 0) continue;
        int mj = 0, mn = 0;
        if (!parse_glibc_version(v.substr(6), mj, mn)) continue;
        if (mj > major || (mj == major && mn > minor)) {
            major = mj;
            minor = mn;
        }
        any = true;
    }
    return any && major >= 0;
}

} // namespace

Core1VerifyResult verify_against_profile(const DependencyReport& deps,
                                         const Tux32Profile& profile) {
    Core1VerifyResult r;
    r.profile_id = profile.id;
    r.profile_version = profile.spec_version;
    r.cpu_baseline = profile.cpu_baseline;
    r.glibc_ceiling = profile.glibc_ceiling();
    r.selected_executable = deps.root.string();
    r.architecture = deps.root_info.arch();

    // Bucket the dependency closure by classification.
    for (const Dependency& d : deps.dependencies) {
        switch (d.kind) {
        case DependencyKind::HostInterface:
            r.host_interfaces.push_back(d.soname);
            break;
        case DependencyKind::Bundle:
            r.bundle_candidates.push_back(d.soname);
            break;
        case DependencyKind::Forbidden:
            r.forbidden.push_back(d.soname);
            break;
        case DependencyKind::Unresolved:
            r.unresolved.push_back(d.soname);
            break;
        case DependencyKind::LanguageRuntime:
            break;
        }
    }

    // The PACKAGE's glibc requirement = the executable + every bundled library
    // (host libraries are supplied by the host and are not the package's need).
    int req_major = -1, req_minor = -1;
    const auto consider = [&](const std::string& object,
                              const std::vector<std::string>& needs) {
        int mj = 0, mn = 0;
        if (!max_glibc_of(needs, mj, mn)) return;
        if (mj > req_major || (mj == req_major && mn > req_minor)) {
            req_major = mj;
            req_minor = mn;
        }
        if (!profile.within_glibc_ceiling(mj, mn)) {
            r.symbol_offenders.push_back(
                {object, "GLIBC_" + std::to_string(mj) + "." + std::to_string(mn)});
        }
    };
    // The executable's own name, not a placeholder: "<executable> requires
    // GLIBC_2.34" was shown verbatim to users in `lexe analyze`, `lexe sdk
    // verify`, `lexe inspect` and the Builder's build report.
    const std::string root_name = deps.root.filename().string();
    consider(root_name.empty() ? std::string("the executable") : root_name,
             deps.root_info.version_needs);
    for (const Dependency& d : deps.dependencies) {
        if (d.kind == DependencyKind::Bundle) {
            consider(d.soname, d.version_needs);
        }
    }
    if (req_major >= 0) {
        r.required_glibc =
            std::to_string(req_major) + "." + std::to_string(req_minor);
    }

    if (!r.unresolved.empty()) {
        r.notes.push_back("Dependency closure is incomplete: " +
                          std::to_string(r.unresolved.size()) +
                          " unresolved soname(s); analysis may be partial.");
    }

    // Verdict precedence (documented): structural, then symbol ceiling, then
    // driver passthrough, then closure completeness.
    if (!deps.root_info.is_elf) {
        r.verdict = Core1Verdict::InvalidInput;
        r.detail = "the target is not an analyzable ELF binary.";
    } else if (!deps.root_info.dynamically_linked()) {
        r.verdict = Core1Verdict::UnsupportedExecutable;
        r.detail = "Core 1 requires a dynamically linked ELF executable; this "
                   "object is not dynamically linked.";
    } else if (!profile.supports_arch(r.architecture)) {
        r.verdict = Core1Verdict::UnsupportedArchitecture;
        r.detail = "architecture \"" +
                   (r.architecture.empty() ? std::string("unknown")
                                           : r.architecture) +
                   "\" is not supported by " + profile.id + ".";
    } else if (!r.symbol_offenders.empty()) {
        r.verdict = Core1Verdict::SymbolCeilingExceeded;
        r.detail = "requires glibc " + r.required_glibc + ", above the Core 1 " +
                   r.glibc_ceiling +
                   " ceiling. Rebuild against a Core 1 sysroot (glibc <= " +
                   r.glibc_ceiling + ").";
    } else if (!r.forbidden.empty()) {
        r.verdict = Core1Verdict::ForbiddenDependency;
        r.detail = "needs host driver/GPU interface(s) that must not be "
                   "bundled; not Core 1 portable without host passthrough.";
    } else if (!r.unresolved.empty()) {
        r.verdict = Core1Verdict::UnresolvedDependency;
        r.detail = "has unresolved dependency(ies); bundle them or confirm the "
                   "host provides them.";
    } else {
        r.verdict = r.notes.empty() ? Core1Verdict::Conformant
                                    : Core1Verdict::ConformantWithNotes;
        r.detail = "satisfies Tux32 " + profile.id + " (glibc <= " +
                   r.glibc_ceiling + ", " + r.architecture + ", dynamic ELF).";
    }
    return r;
}

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
