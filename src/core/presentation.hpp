#pragma once
// presentation — frontend-neutral display model (runtime-trust WS10). ONE place
// turns the raw typed states (authenticity + local trust, permissions, isolation
// capability) into truthful, display-ready values that BOTH the CLI and the GTK
// frontends render identically. It never invents the words "verified", "trusted"
// (unqualified), "safe" or "secure": a valid signature is presented as
// consistency with a key, first-seen is never styled as externally verified, and
// a control is only ever called "enforced" when the backend can actually
// establish it.

#include "core/isolation.hpp"
#include "core/permissions.hpp"
#include "core/trust.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace lexe::presentation {

// ---------------------------------------------------- authenticity + trust

/// A two-dimensional authenticity + local-trust summary. `severity` is a styling
/// hint only — NEVER a claim of external verification.
struct AuthenticityView {
    enum class Severity {
        Ok,      // valid signature by a known / explicitly-trusted key
        Caution, // valid signature, first-seen key — identity NOT verified
        Danger,  // invalid signature / changed key / blocked / corrupt / conflict
    };
    Severity severity = Severity::Danger;
    std::string headline;        // short state label (no "verified")
    std::string signature_text;  // "Signature: valid (Ed25519)" etc.
    std::string key_text;        // the local key-state sentence
    std::string identity_caveat; // ALWAYS present: TOFU, not real-world identity
    std::string publisher_display;   // the free-form publisher string (unverified)
    std::string fingerprint_grouped; // display fingerprint of the presented key
    std::string fingerprint_full;    // full fingerprint (for structured output)
    bool can_proceed = false;        // the trust decision allows proceeding
};
const char* to_string(AuthenticityView::Severity s);

/// Build the authenticity view from a trust evaluation and the (unverified)
/// publisher display string.
AuthenticityView present_authenticity(const TrustEvaluation& eval,
                                      const std::string& publisher_display);

// --------------------------------------------------------- permissions

/// Human label for a permission id (the vocabulary title; unknown ids pass
/// through unchanged).
std::string describe_permission(const std::string& id);

/// The TRUTHFUL enforcement state of a permission on this platform, given a
/// probed isolation capability: "enforced …", "advisory …", "unavailable", or
/// "not enforced on this platform".
std::string permission_enforcement(const std::string& id,
                                   const IsolationCapabilities& caps);

struct PermissionView {
    std::string id;
    std::string title;
    std::string enforcement;
};
/// Present a permission set with per-permission enforcement.
std::vector<PermissionView>
present_permissions(const std::vector<std::string>& permission_ids,
                    const IsolationCapabilities& caps);

/// Present a permission delta (update) — added/removed/unchanged are kept
/// SEPARATE and never merged with a key-change decision.
struct PermissionDeltaView {
    std::vector<std::string> added;     // human titles
    std::vector<std::string> removed;
    std::vector<std::string> unchanged;
    bool expands = false;
};
PermissionDeltaView present_permission_delta(const PermissionDelta& delta);

// --------------------------------------------------------- isolation

/// A truthful isolation-capability summary for the current platform.
struct IsolationView {
    std::string headline;        // "Baseline isolation is enforced", etc.
    std::string detail;          // the backend's own reason string
    std::string platform_caveat; // what this platform does and does NOT provide
    // (control label, truthful state) rows.
    std::vector<std::pair<std::string, std::string>> controls;
};
IsolationView present_isolation(const IsolationCapabilities& caps);

// ------------------------------------------------- package display fields
//
// The plain facts about a package — size, type, scope, source, update policy.
// These are NOT security claims, but they are shown side by side with the ones
// that are, and every frontend must state them identically. They live here for
// the same reason the trust and permission text does: the CLI and the GTK
// frontends each grew their own copy, and the copies drifted: the Installer
// called a permission "Access to files you select" while the frozen vocabulary
// (and therefore the CLI) said "Access to files you choose", and one wrote an em
// dash in the type line where the other wrote a hyphen. Where the two disagreed,
// SPEC.md's "Opening a .lexe File" mock is the tie-breaker. One implementation,
// one wording, both frontends.

/// Human-readable byte size in decimal units, e.g. 125829120 -> "126 MB".
std::string format_size(std::uint64_t bytes);

/// The "Application Type" line, e.g. "Native Linux - x86_64". `host_arch` is
/// shown alone when the package supports it; otherwise every architecture the
/// package offers is listed, so the reader can see why it will not run here.
std::string application_type_line(const std::string& application_type,
                                  const std::vector<std::string>& architectures,
                                  const std::string& host_arch);

/// The install-scope line, e.g. "Current user only".
std::string install_scope_line(const std::string& scope);

/// The update-policy line. A package with updates disabled, or with no manifest
/// URL to check, has no automatic updates and is described as such.
std::string updates_line(bool enabled, const std::string& manifest_url,
                         const std::string& channel);

/// The "Source" line. 0.1 supports bundled packages only.
std::string source_line(const std::string& install_mode,
                        const std::string& package_filename);

/// The canonical short label for a LOCAL trust state ("blocked",
/// "explicitly-trusted", "corrupt", "known", "first-seen"). One place, because
/// `lexe apps` and `lexe info` each wrote their own and disagreed: apps labelled
/// an explicitly-trusted key "trusted locally (first-use)" — appending
/// "(first-use)" to every state including the one that is not first use —
/// directly contradicting `lexe info` and `lexe trust show`.
std::string local_trust_label(const std::string& state);

/// The install size to display: the manifest's estimate when it declares one,
/// otherwise the package's actual uncompressed payload size. Either may be 0
/// (unknown), which yields an empty string rather than a fabricated figure.
std::string install_size_line(std::uint64_t estimated_size,
                              std::uint64_t payload_bytes);

} // namespace lexe::presentation
