// execpolicy — see execpolicy.hpp (Definitive Architecture §6, §7, §8).

#include "lexe/runtime/execpolicy.hpp"

#include "lexe/base/util.hpp"
#include "lexe/sandbox/isolation.hpp"
#include "lexe/verify/verify.hpp"

#include <algorithm>
#include <filesystem>
#include <system_error>

namespace fs = std::filesystem;

namespace lexe {

namespace {

/// The providers this runtime knows how to look for. `candidates` are the
/// executable names/paths tried in order; the first that exists wins.
///
/// What each id MEANS is `chain_layer_kind()` in the manifest layer, because
/// these ids are manifest vocabulary (`execution.allowedChains`). This table
/// only says where to find them.
struct ProviderSpec {
    const char* id;
    const char* name;
    const char* guest_isa; // "" for foreign-OS providers
    std::vector<const char*> candidates;
};

const std::vector<ProviderSpec>& provider_specs() {
    static const std::vector<ProviderSpec> kSpecs = {
        {"fex", "FEX-Emu", "x86_64", {"FEXInterpreter", "FEXLoader"}},
        {"box64", "Box64", "x86_64", {"box64"}},
        {"qemu-user", "QEMU user-mode", "x86_64",
         {"qemu-x86_64", "qemu-x86_64-static"}},
        {"wine", "Wine", "", {"wine", "wine64"}},
        // Proton is in this table for completeness only: it is not a
        // distribution package and is never on $PATH. It is found by
        // provider_search_paths() below, which is the whole reason that
        // function exists.
        {"proton", "Proton", "", {"proton"}},
    };
    return kSpecs;
}

/// Directories that hold Proton builds, in the order they are searched.
///
/// These are the real locations, ordered the way a user would expect them to
/// win: third-party builds (GE-Proton and friends live in
/// compatibilitytools.d), then Valve's own under steamapps/common, then a
/// system-wide install. Within one directory the entries are sorted by name so
/// the choice is reproducible across runs instead of depending on readdir order.
///
/// Deliberately NOT version-aware. Ordering "GE-Proton11-7" against
/// "GE-Proton9-1" correctly needs a version parser for a vocabulary nobody
/// controls, and a wrong guess silently runs a different Proton than the user
/// thinks. A documented stable first-match plus LEXE_PROTON for anything else
/// is a rule that fits in someone head; `lexe runtime` prints which build was
/// chosen and what else was seen.
std::vector<std::string> proton_roots() {
    std::vector<std::string> roots;
    const std::string home = util::get_env("HOME").value_or("");
    if (home.empty()) return roots;
    for (const char* relative : {
             "/.steam/root/compatibilitytools.d",
             "/.steam/steam/compatibilitytools.d",
             "/.local/share/Steam/compatibilitytools.d",
             "/.var/app/com.valvesoftware.Steam/data/Steam/compatibilitytools.d",
             "/.steam/root/steamapps/common",
             "/.steam/steam/steamapps/common",
             "/.local/share/Steam/steamapps/common",
         }) {
        roots.push_back(home + relative);
    }
    roots.push_back("/usr/share/steam/compatibilitytools.d");
    return roots;
}

} // namespace

std::vector<std::string> provider_search_roots(const std::string& id) {
    if (id == "proton") return proton_roots();
    return {};
}

std::vector<std::string> provider_search_paths(const std::string& id) {
    std::vector<std::string> paths;
    if (id == "proton") {
        // An explicit override always wins, and is how an unusual layout — or a
        // test — names one specific build.
        const std::string override_path =
            util::get_env("LEXE_PROTON").value_or("");
        if (!override_path.empty()) paths.push_back(override_path);
        for (const std::string& root : proton_roots()) {
            std::error_code ec;
            if (!fs::is_directory(root, ec)) continue;
            std::vector<std::string> names;
            for (fs::directory_iterator it(root, ec), end; it != end;
                 it.increment(ec)) {
                if (ec) break;
                if (!it->is_directory()) continue;
                names.push_back(it->path().filename().string());
            }
            std::sort(names.begin(), names.end());
            for (const std::string& name : names) {
                paths.push_back(root + "/" + name + "/proton");
            }
        }
        return paths;
    }
    // Everything else is a distribution package, so $PATH is the right answer
    // and the candidate names are in the spec table.
    for (const ProviderSpec& spec : provider_specs()) {
        if (spec.id != id) continue;
        for (const char* candidate : spec.candidates) {
            const std::string resolved = util::find_on_path(candidate);
            if (!resolved.empty()) paths.push_back(resolved);
        }
    }
    return paths;
}

namespace {

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
        if (provider.id == "proton") {
            // Proton entry point is a Python dispatcher, not a loader: bare
            // `proton <exe>` is not a command it has, so a chain built that way
            // could never have run anything. `runinprefix` is the verb that
            // runs the program in the compat prefix, creating the prefix when it
            // does not exist yet, and — unlike `run` — leaves the child stdout
            // and stderr attached to us, which is what lets a failed launch
            // produce a diagnostic carrying the program own output instead of
            // an empty one.
            chain.argv_prefix.push_back("runinprefix");
            // Both of these are mandatory. Without STEAM_COMPAT_DATA_PATH
            // Proton prints "No compat data path?" and exits 1; without
            // STEAM_COMPAT_CLIENT_INSTALL_PATH it dies with a Python KeyError.
            // The values are SANDBOX paths under the application own private
            // data root — where Wine prefix already lands, because HOME is
            // redirected there — so Proton state is the application state and
            // not the user. Nothing of the host real Steam installation is
            // bound, named, or readable from inside.
            chain.env["STEAM_COMPAT_DATA_PATH"] = kSandboxProtonPrefix;
            chain.env["STEAM_COMPAT_CLIENT_INSTALL_PATH"] = kSandboxProtonSteam;
            // Proton needs the compat path to already exist (see the constant).
            chain.required_data_dirs.push_back(".proton");
        }
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
        provider.kind = chain_layer_kind(spec.id);
        provider.guest_isa = spec.guest_isa;
        for (const char* candidate : spec.candidates) {
            const std::string resolved = util::find_on_path(candidate);
            if (!resolved.empty()) {
                provider.available = true;
                provider.executable = resolved;
                provider.origin = "on PATH";
                provider.detail = std::string("found at ") + resolved;
                break;
            }
        }
        // Providers that are not distribution packages live at well-known paths
        // instead. Proton is the case that matters: a PATH-only probe answered
        // "not installed on this host" on a machine with Proton installed, so
        // every Proton chain was reported unavailable and the entire path went
        // unexercised while looking implemented.
        if (!provider.available) {
            for (const std::string& candidate : provider_search_paths(spec.id)) {
                std::error_code ec;
                if (!fs::is_regular_file(candidate, ec)) continue;
                provider.available = true;
                provider.executable = candidate;
                provider.origin =
                    util::get_env("LEXE_PROTON").value_or("") == candidate
                        ? "LEXE_PROTON override"
                        : "Steam compatibility tool";
                provider.detail = "found at " + candidate;
                break;
            }
        }
        if (!provider.available) {
            // Say that it LOOKED, and where to see where. "not installed on
            // this host" on its own is what made a discovery bug read as
            // policy: it is the same sentence whether the runtime searched the
            // right places and found nothing, or searched the wrong place.
            const std::size_t candidates =
                provider_search_paths(spec.id).size();
            const std::size_t roots = provider_search_roots(spec.id).size();
            if (candidates > 0) {
                provider.detail =
                    "not installed on this host (considered " +
                    std::to_string(candidates) + " candidate" +
                    (candidates == 1 ? "" : "s") + "; `lexe runtime show " +
                    spec.id + "` lists them)";
            } else if (roots > 0) {
                provider.detail =
                    "not installed on this host (searched " +
                    std::to_string(roots) +
                    " locations, none of which exist; `lexe runtime show " +
                    spec.id + "` lists them)";
            } else {
                provider.detail = "not installed on this host (not on $PATH)";
            }
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
    // What runs, once installed, is a Linux-native binary in both 0.1 cases: a
    // "native" package carries one, and a "portable" package was COMPILED into
    // one on this host at install time — which is exactly why portable satisfies
    // even the strict resolver. The check is written as an explicit enumeration
    // rather than "not foreign" so a future foreign-OS payload type cannot slip
    // through §6 by default.
    const bool linux_native =
        manifest.application_kind == ApplicationType::Native ||
        manifest.application_kind == ApplicationType::Portable;

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
