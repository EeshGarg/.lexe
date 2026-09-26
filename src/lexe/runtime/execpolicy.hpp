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

#include <map>
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
    /// Where this provider was found, in words a user can act on: "on PATH",
    /// "Steam compatibility tool", "LEXE_PROTON override". Recorded because
    /// "Proton was found" is not a useful thing to be told when a machine has
    /// four of them and the runtime picked one.
    std::string origin;
};

/// Every provider this runtime knows how to look for, with its host state.
struct ProviderSet {
    std::vector<Provider> providers;

    const Provider* find(const std::string& id) const;
    bool has(const std::string& id) const;
    std::vector<Provider> available() const;
};

/// Probe the host for compatibility providers. Cheap (PATH lookups and
/// directory listings); never executes a provider.
ProviderSet probe_providers();

/// Every absolute path `probe_providers()` will consider for `id`, in the order
/// it considers them, whether or not anything is there.
///
/// Exposed because provider discovery is the part of the compatibility story
/// that is easiest to get wrong and hardest to notice: Proton is never on
/// $PATH, so a PATH-only probe reports "not installed on this host" on a
/// machine with four Proton builds on it. `lexe runtime` prints this list so
/// the answer to "why can't it find mine?" is inspectable instead of guessed
/// at, and tests assert against it without needing a Proton installed.
std::vector<std::string> provider_search_paths(const std::string& id);

/// The DIRECTORIES `provider_search_paths(id)` looks inside, in order, whether
/// or not they exist.
///
/// Separate from the candidates because the two answer different questions, and
/// the difference matters exactly when something is missing: with no Steam
/// installation at all there are no candidates, so a message built only from
/// candidates can say nothing more useful than "not installed" — which is what
/// sent a previous session looking for a policy bug instead of a discovery one.
/// Empty for a provider found on $PATH, which is its own explanation.
std::vector<std::string> provider_search_roots(const std::string& id);

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
    ///
    /// This is not always just the executable. Proton's entry point is a
    /// dispatcher that requires a verb, so its prefix is
    /// {"<path>/proton", "runinprefix"} — invoking it without one does nothing
    /// at all, which is how a Proton chain can look correct and never have run.
    std::vector<std::string> argv_prefix;

    /// Environment this chain REQUIRES, as name -> value. Merged into the
    /// sandbox's allowlisted environment by the isolation layer.
    ///
    /// It exists for Proton, which refuses to start without
    /// STEAM_COMPAT_DATA_PATH and STEAM_COMPAT_CLIENT_INSTALL_PATH and exits 1
    /// with a Python KeyError if either is absent. Values are SANDBOX paths,
    /// not host paths: the chain says what it needs, the sandbox decides where
    /// that lives, and nothing of the host's real Steam installation is
    /// exposed to the application.
    std::map<std::string, std::string> env;

    /// Directories this chain needs to exist before exec, relative to the
    /// application private DATA root. Created by the launcher.
    ///
    /// Proton is why: it requires STEAM_COMPAT_DATA_PATH to name an existing
    /// directory and does not create one, failing with
    /// "chdir to <path>/pfx : No such file or directory" when it is missing.
    /// Expressed as chain data rather than as a special case in the launcher, so
    /// the launcher stays free of per-provider knowledge and a test can assert
    /// what a chain asks for without running it.
    std::vector<std::string> required_data_dirs;
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
