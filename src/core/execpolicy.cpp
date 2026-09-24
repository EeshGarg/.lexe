// execpolicy — see execpolicy.hpp (Definitive Architecture §6, §7, §8).

#include "core/execpolicy.hpp"

#include "core/util.hpp"
#include "core/verify.hpp"

#include <algorithm>
#include <filesystem>
#include <system_error>

namespace fs = std::filesystem;

namespace lexe {

namespace {

/// The providers this runtime knows how to look for. `candidates` are the
/// executable names/paths tried in order; the first that exists wins.
struct ProviderSpec {
    const char* id;
    const char* name;
    ProviderKind kind;
    const char* guest_isa; // "" for foreign-OS providers
    std::vector<const char*> candidates;
};

const std::vector<ProviderSpec>& provider_specs() {
    static const std::vector<ProviderSpec> kSpecs = {
        {"fex", "FEX-Emu", ProviderKind::IsaTranslation, "x86_64",
         {"FEXInterpreter", "FEXLoader"}},
        {"box64", "Box64", ProviderKind::IsaTranslation, "x86_64", {"box64"}},
        {"qemu-user", "QEMU user-mode", ProviderKind::IsaTranslation, "x86_64",
         {"qemu-x86_64", "qemu-x86_64-static"}},
        {"wine", "Wine", ProviderKind::ForeignOs, "", {"wine", "wine64"}},
        {"proton", "Proton", ProviderKind::ForeignOs, "", {"proton"}},
    };
    return kSpecs;
}

/// Search PATH for `name` and return the absolute path, or "" when absent.
/// Never executes anything (probing must be cheap and side-effect free).
std::string which(const std::string& name) {
    if (name.find('/') != std::string::npos) {
        std::error_code ec;
        return fs::is_regular_file(name, ec) ? name : std::string();
    }
    const std::optional<std::string> path_env = util::get_env("PATH");
    if (!path_env.has_value()) return {};
    std::size_t start = 0;
    while (start <= path_env->size()) {
        const std::size_t sep = path_env->find(':', start);
        const std::string dir = path_env->substr(
            start, sep == std::string::npos ? std::string::npos : sep - start);
        if (!dir.empty()) {
            const fs::path candidate = fs::path(dir) / name;
            std::error_code ec;
            if (fs::is_regular_file(candidate, ec)) {
                const fs::perms p = fs::status(candidate, ec).permissions();
                if (!ec && (p & fs::perms::owner_exec) != fs::perms::none) {
                    return candidate.string();
                }
            }
        }
        if (sep == std::string::npos) break;
        start = sep + 1;
    }
    return {};
}

/// The chain that runs the application directly — the boring fast path (§16).
ExecutionChain native_chain() {
    ExecutionChain chain;
    chain.id = "native";
    chain.native = true;
    chain.explanation =
        "Native execution: the host-ISA Linux binary runs directly, with no "
        "compatibility layer in the steady-state execution path.";
    return chain;
}

ExecutionChain chain_from_provider(const Provider& provider) {
    ExecutionChain chain;
    chain.id = provider.id;
    chain.layers = {provider.id};
    chain.native = false;
    if (provider.kind == ProviderKind::IsaTranslation) {
        chain.explanation = provider.name +
                            " translates the package's " + provider.guest_isa +
                            " instructions for this host.";
    } else {
        chain.explanation =
            provider.name + " runs the package's foreign-OS binary on Linux.";
    }
    if (!provider.executable.empty()) {
        chain.argv_prefix = {provider.executable};
    }
    return chain;
}

/// A layered chain such as "proton+fex" (§8 "Wine / Proton + ISA translation"):
/// the foreign-OS layer is outermost, the ISA layer innermost.
std::optional<ExecutionChain> layered_chain(const std::string& id,
                                            const ProviderSet& providers) {
    const std::size_t plus = id.find('+');
    if (plus == std::string::npos) return std::nullopt;
    const std::string outer_id = id.substr(0, plus);
    const std::string inner_id = id.substr(plus + 1);
    const Provider* outer = providers.find(outer_id);
    const Provider* inner = providers.find(inner_id);
    if (outer == nullptr || inner == nullptr) return std::nullopt;
    if (outer->kind != ProviderKind::ForeignOs ||
        inner->kind != ProviderKind::IsaTranslation) {
        return std::nullopt;
    }
    ExecutionChain chain;
    chain.id = id;
    chain.layers = {outer_id, inner_id};
    chain.native = false;
    chain.explanation = inner->name + " translates the instruction set and " +
                        outer->name + " provides the foreign-OS environment.";
    if (!inner->executable.empty() && !outer->executable.empty()) {
        chain.argv_prefix = {inner->executable, outer->executable};
    }
    return chain;
}

/// Is a chain id structurally usable on this host (all its layers present)?
bool chain_available(const ExecutionChain& chain, const ProviderSet& providers,
                     std::string& why_not) {
    if (chain.native) return true;
    for (const std::string& layer : chain.layers) {
        const Provider* p = providers.find(layer);
        if (p == nullptr) {
            why_not = "unknown provider \"" + layer + "\"";
            return false;
        }
        if (!p->available) {
            why_not = p->name + " is not installed on this host";
            return false;
        }
    }
    return true;
}

} // namespace

const char* to_string(ProviderKind k) {
    switch (k) {
    case ProviderKind::IsaTranslation: return "isa-translation";
    case ProviderKind::ForeignOs: return "foreign-os";
    }
    return "isa-translation";
}

const Provider* ProviderSet::find(const std::string& id) const {
    for (const Provider& p : providers) {
        if (p.id == id) return &p;
    }
    return nullptr;
}

bool ProviderSet::has(const std::string& id) const {
    const Provider* p = find(id);
    return p != nullptr && p->available;
}

std::vector<Provider> ProviderSet::available() const {
    std::vector<Provider> out;
    for (const Provider& p : providers) {
        if (p.available) out.push_back(p);
    }
    return out;
}

ProviderSet probe_providers() {
    ProviderSet set;
    for (const ProviderSpec& spec : provider_specs()) {
        Provider provider;
        provider.id = spec.id;
        provider.name = spec.name;
        provider.kind = spec.kind;
        provider.guest_isa = spec.guest_isa;
        for (const char* candidate : spec.candidates) {
            const std::string resolved = which(candidate);
            if (!resolved.empty()) {
                provider.available = true;
                provider.executable = resolved;
                provider.detail = std::string("found at ") + resolved;
                break;
            }
        }
        if (!provider.available) {
            provider.detail = "not installed on this host";
        }
        set.providers.push_back(std::move(provider));
    }
    return set;
}

HostFacts detect_host() {
    HostFacts facts;
    facts.isa = host_architecture();
    facts.os = "linux";
    return facts;
}

std::vector<std::string> known_chain_ids() {
    std::vector<std::string> ids = {"native"};
    for (const ProviderSpec& spec : provider_specs()) {
        ids.push_back(spec.id);
    }
    // The documented layered combinations from §8.
    ids.push_back("proton+fex");
    ids.push_back("proton+box64");
    ids.push_back("wine+fex");
    ids.push_back("wine+box64");
    return ids;
}

std::optional<ExecutionChain> make_chain(const std::string& id,
                                         const ProviderSet& providers) {
    if (id == "native") return native_chain();
    if (id.find('+') != std::string::npos) return layered_chain(id, providers);
    if (const Provider* p = providers.find(id)) {
        return chain_from_provider(*p);
    }
    return std::nullopt;
}

ChainResolution resolve_chain(const Manifest& manifest, const AppConfig& config,
                              const HostFacts& host,
                              const ProviderSet& providers) {
    ChainResolution resolution;
    resolution.mission_critical = manifest.mission_critical;

    // A launch reference does not itself execute anything; it names an app.
    if (manifest.role != PackageRole::Application) {
        resolution.ok = false;
        resolution.reason =
            "a launch reference has no execution chain of its own; resolve the "
            "application it points at";
        return resolution;
    }

    const bool host_isa_native =
        std::find(manifest.architectures.begin(), manifest.architectures.end(),
                  host.isa) != manifest.architectures.end();
    // 0.1 packages are Linux-native by construction (applicationType "native"),
    // but the check is written explicitly so a future foreign-OS payload type
    // cannot silently slip through the strict resolver.
    const bool linux_native = manifest.application_type == "native";

    // ---------------------------------------------------------- §6 STRICT
    if (manifest.mission_critical) {
        resolution.strict_resolver = true;
        if (!linux_native) {
            resolution.reason =
                "mission-critical execution requires a Linux-native "
                "representation; this package does not provide one. Execution "
                "stops — compatibility fallback is forbidden.";
            return resolution;
        }
        if (!host_isa_native) {
            resolution.reason =
                "mission-critical execution requires a host-ISA-native "
                "realization for " + host.isa +
                ", and this package declares none. ISA translation is "
                "forbidden for mission-critical software, so execution stops.";
            return resolution;
        }
        resolution.ok = true;
        resolution.chain = native_chain();
        resolution.reason =
            "mission-critical: strict native execution (Linux-native, " +
            host.isa + "-native, verified package).";
        // Deliberately NO alternatives: §6 forbids offering any other chain.
        return resolution;
    }

    // ---------------------------------------------------------- §8 NORMAL
    // Candidate order = the publisher's preference order, with the native path
    // always considered first when it is genuinely possible.
    std::vector<std::string> candidate_ids;
    if (linux_native && host_isa_native && manifest.chain_allowed("native")) {
        candidate_ids.push_back("native");
    }
    for (const std::string& id : manifest.effective_allowed_chains()) {
        if (id == "native") continue;
        if (std::find(candidate_ids.begin(), candidate_ids.end(), id) ==
            candidate_ids.end()) {
            candidate_ids.push_back(id);
        }
    }

    // Build the permitted-and-available set, recording WHY anything permitted
    // was dropped so the UI never silently hides a chain.
    std::vector<ExecutionChain> usable;
    for (const std::string& id : candidate_ids) {
        const std::optional<ExecutionChain> chain = make_chain(id, providers);
        if (!chain.has_value()) {
            resolution.rejected.push_back(
                {id, "this runtime does not know the chain \"" + id + "\""});
            continue;
        }
        if (chain->native && !(linux_native && host_isa_native)) {
            resolution.rejected.push_back(
                {id, "the package provides no " + host.isa +
                         "-native Linux binary for this host"});
            continue;
        }
        std::string why_not;
        if (!chain_available(*chain, providers, why_not)) {
            resolution.rejected.push_back({id, why_not});
            continue;
        }
        usable.push_back(*chain);
    }

    if (usable.empty()) {
        resolution.reason =
            "no execution chain permitted by this package is available on "
            "this host";
        return resolution;
    }

    // §10: the user's preference may REORDER or NARROW the usable set — never
    // extend it. Anything the user asked for that policy forbids is reported,
    // not silently honoured and not silently dropped.
    std::vector<ExecutionChain> ordered = usable;
    if (config.compatibility_mode == CompatibilityMode::Manual &&
        !config.preferred_chain.empty()) {
        std::vector<ExecutionChain> preferred;
        for (const std::string& id : config.preferred_chain) {
            const auto it = std::find_if(
                usable.begin(), usable.end(),
                [&](const ExecutionChain& c) { return c.id == id; });
            if (it != usable.end()) {
                if (std::find_if(preferred.begin(), preferred.end(),
                                 [&](const ExecutionChain& c) {
                                     return c.id == id;
                                 }) == preferred.end()) {
                    preferred.push_back(*it);
                }
            } else if (!manifest.chain_allowed(id)) {
                resolution.rejected.push_back(
                    {id, "your preference is not permitted by this package's "
                         "execution policy"});
            } else {
                resolution.rejected.push_back(
                    {id, "your preference is permitted but not available on "
                         "this host"});
            }
        }
        if (!preferred.empty()) {
            // Manual mode means "these, in this order"; anything not listed
            // stays available as an alternative but is not auto-selected.
            for (const ExecutionChain& c : usable) {
                if (std::find_if(preferred.begin(), preferred.end(),
                                 [&](const ExecutionChain& p) {
                                     return p.id == c.id;
                                 }) == preferred.end()) {
                    preferred.push_back(c);
                }
            }
            ordered = std::move(preferred);
        }
    }

    resolution.ok = true;
    resolution.chain = ordered.front();
    resolution.alternatives.assign(ordered.begin() + 1, ordered.end());
    if (resolution.chain.native) {
        resolution.reason =
            "native execution is possible and preferred: no compatibility "
            "layer is required, so none is used.";
    } else if (config.compatibility_mode == CompatibilityMode::Manual) {
        resolution.reason = "selected by your compatibility preference for "
                            "this application: " +
                            resolution.chain.explanation;
    } else {
        resolution.reason = "native execution is not possible here; " +
                            resolution.chain.explanation;
    }
    return resolution;
}

} // namespace lexe
