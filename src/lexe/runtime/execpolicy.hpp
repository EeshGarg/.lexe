#pragma once
// execpolicy — the execution resolver of the Definitive Architecture (§6 mission
// -critical policy, §7 install+run flow, §8 normal compatibility behaviour).
//
// This is the module that answers "HOW will this application actually run on
// THIS machine?", and it is deliberately split the same way the architecture
// is:
//
//   READ EXECUTION POLICY
//        |
//        +-- isMissionCritical = TRUE  --> STRICT RESOLVER
//        |      Linux-native + host-ISA-native + verified, or STOP.
//        |      No ISA translation, no Wine/Proton, no foreign-OS execution,
//        |      no compatibility fallback, no "run anyway".
//        |
//        +-- isMissionCritical = FALSE --> NORMAL RESOLVER
//               native when possible; ISA translation / Wine / Proton /
//               combined layers when needed AND permitted AND available.
//
// Three independent inputs decide the outcome and are never collapsed:
//   1. the PACKAGE POLICY   — manifest.execution (signed; the publisher's word)
//   2. the USER PREFERENCE  — appconfig (§10; can only narrow/reorder #1)
//   3. the HOST REALITY     — which providers are actually installed here
//
// The resolver is pure with respect to #1 and #2; #3 enters through a probed
// ProviderSet so the decision logic stays deterministically testable.

#include "lexe/state/appconfig.hpp"
#include "lexe/package/manifest.hpp"

#include <optional>
#include <string>
#include <vector>

namespace lexe {

/// What a compatibility provider DOES — the architecture treats these
/// categories differently under mission-critical policy (§6 FORBID).
///
/// This is the manifest's vocabulary (`ChainLayerKind`), not a second copy of
/// it: `execution.allowedChains` names these layers, so what the names MEAN
/// belongs beside the manifest, and what this module adds is how to find and
/// invoke them. Two enums for one idea is two things that can drift.
using ProviderKind = ChainLayerKind;

/// One compatibility provider as found (or not found) on THIS host.
struct Provider {
    std::string id;         // "fex", "box64", "wine", "proton", "qemu-user"
    std::string name;       // display name
    ProviderKind kind = ProviderKind::IsaTranslation;
    bool available = false; // an executable was actually found on this host
    std::string executable; // absolute path when available, else ""
    std::string detail;     // truthful explanation (version / why missing)
    /// ISA the provider can EXECUTE (the guest ISA), e.g. "x86_64". Empty for
    /// foreign-OS providers, which are ISA-agnostic on their own.
    std::string guest_isa;
};

/// Every provider this runtime knows how to look for, with its host state.
struct ProviderSet {
    std::vector<Provider> providers;

    const Provider* find(const std::string& id) const;
    bool has(const std::string& id) const;
    std::vector<Provider> available() const;
};

/// Probe the host for compatibility providers. Cheap (PATH lookups + a
/// well-known path check); never executes a provider.
ProviderSet probe_providers();

/// A concrete way to run the application. "native" has no layers at all —
/// the architecture's boring fast path (§16).
struct ExecutionChain {
    /// Canonical id: "native", "fex", "box64", "wine", "proton",
    /// or layered as "proton+fex" (outermost first, matching §8's naming).
    std::string id;
    /// Provider ids applied, outermost first. Empty for the native chain.
    std::vector<std::string> layers;
    bool native = false;
    /// Human-first explanation of what this chain does.
    std::string explanation;

    /// The argv prefix this chain contributes, e.g. {"/usr/bin/box64"}. Empty
    /// for native. The application's own entrypoint and arguments follow.
    std::vector<std::string> argv_prefix;
};

/// Why a candidate chain was not selected — kept so the UI can show the user
/// what exists but is unavailable, instead of silently hiding it.
struct RejectedChain {
    std::string id;
    std::string reason;
};

/// The outcome of resolving how to run an application.
struct ChainResolution {
    bool ok = false;
    ExecutionChain chain;         // valid only when ok
    std::string reason;           // why THIS chain (or why none)
    bool mission_critical = false;
    bool strict_resolver = false; // the strict path was taken
    /// Other chains that are permitted by policy AND available on this host —
    /// exactly the list a power user may choose from (§8 "Only chains allowed
    /// by the package policy are shown").
    std::vector<ExecutionChain> alternatives;
    std::vector<RejectedChain> rejected;
};

/// Everything the resolver needs about the host.
struct HostFacts {
    std::string isa;          // host_architecture(): "x86_64" / "aarch64"
    std::string os = "linux"; // this runtime targets Linux hosts
};
HostFacts detect_host();

/// Resolve the execution chain for `manifest` on `host`, honouring the user's
/// per-application overrides and the providers actually present.
///
/// Pure: no filesystem or process effects. `providers` carries the host truth.
ChainResolution resolve_chain(const Manifest& manifest, const AppConfig& config,
                              const HostFacts& host,
                              const ProviderSet& providers);

/// Every chain id this runtime understands, for help text and validation.
std::vector<std::string> known_chain_ids();

/// Build the ExecutionChain value for a known id (native or provider-based),
/// using `providers` for argv resolution. Returns nullopt for an unknown id.
std::optional<ExecutionChain> make_chain(const std::string& id,
                                         const ProviderSet& providers);

} // namespace lexe
