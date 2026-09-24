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

// ------------------------------------------------------------ signer class

/// The signer vocabulary of the Definitive Architecture §4. It is a TAXONOMY,
/// and this runtime implements only the part of it that it can establish
/// truthfully. Cryptographic validity and signer trust are separate concepts:
/// a valid signature proves provenance and integrity; it does NOT by itself
/// prove that the software is safe, or who the publisher is in the real world.
enum class SignerClass {
    UshaVerified,       // NOT AVAILABLE — needs a signing authority
    OrganizationSigned, // NOT AVAILABLE — needs organizational attestation
    DeveloperSigned,    // valid signature by the key already bound to this App ID
    LocallyTrusted,     // that key was EXPLICITLY trusted on this machine
    UnknownSigner,      // valid signature, first-seen key: identity not established
    InvalidSignature,   // the signature did not verify, or the key changed
};
const char* to_string(SignerClass c);

/// One row of the §4 taxonomy, including whether this runtime can actually
/// establish it. A frontend that shows the taxonomy must show the unavailable
/// tiers as unavailable rather than quietly omitting them — otherwise a user
/// could reasonably infer that "Developer Signed" is the top of the scale.
struct SignerClassInfo {
    SignerClass signer_class = SignerClass::UnknownSigner;
    std::string id;          // "usha-verified"
    std::string name;        // "Usha Verified"
    std::string meaning;     // what it would assert
    bool available = false;  // can THIS runtime ever assign it?
    std::string unavailable_reason; // why not, when it cannot
};
const std::vector<SignerClassInfo>& signer_classes();
const SignerClassInfo& signer_class_info(SignerClass c);

/// Classify a trust evaluation into the §4 vocabulary. Never returns a class
/// this runtime cannot establish.
SignerClass classify_signer(const TrustEvaluation& eval);

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

} // namespace lexe::presentation
