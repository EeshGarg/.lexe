// presentation — see presentation.hpp. Pure, frontend-neutral formatting.

#include "core/presentation.hpp"

namespace lexe::presentation {

const char* to_string(AuthenticityView::Severity s) {
    switch (s) {
    case AuthenticityView::Severity::Ok:      return "ok";
    case AuthenticityView::Severity::Caution: return "caution";
    case AuthenticityView::Severity::Danger:  return "danger";
    }
    return "?";
}

namespace {

std::string signature_label(SignatureState s) {
    switch (s) {
    case SignatureState::Valid:                return "valid (Ed25519)";
    case SignatureState::Invalid:              return "NOT valid";
    case SignatureState::Malformed:            return "malformed package";
    case SignatureState::UnsupportedAlgorithm: return "unsupported algorithm";
    case SignatureState::Missing:              return "missing";
    }
    return "unknown";
}

} // namespace

AuthenticityView present_authenticity(const TrustEvaluation& eval,
                                      const std::string& publisher_display) {
    AuthenticityView v;
    v.publisher_display = publisher_display;
    v.fingerprint_grouped = eval.presented.grouped;
    v.fingerprint_full = eval.presented.full;
    v.signature_text = "Signature: " + signature_label(eval.signature);
    v.identity_caveat =
        "A valid signature proves the package is consistent with this key — not "
        "the publisher's real-world identity. This is a local trust decision.";
    v.can_proceed = eval.allowed();

    switch (eval.key_state) {
    case PublisherKeyState::FirstSeen:
        v.severity = AuthenticityView::Severity::Caution;
        v.headline = "Signed — publisher not verified (first seen)";
        v.key_text = "Publisher key: first seen on this machine; not previously "
                     "trusted here.";
        break;
    case PublisherKeyState::KnownMatching:
        v.severity = AuthenticityView::Severity::Ok;
        v.headline = "Signed by the known publisher key";
        v.key_text = "Publisher key: matches the key already associated with "
                     "this application on this machine.";
        break;
    case PublisherKeyState::ExplicitlyTrusted:
        v.severity = AuthenticityView::Severity::Ok;
        v.headline = "Signed by a key you trust locally";
        v.key_text = "Publisher key: explicitly trusted by you on this machine "
                     "(a local decision, not external identity verification).";
        break;
    case PublisherKeyState::Changed:
        v.severity = AuthenticityView::Severity::Danger;
        v.headline = "Refused — the signing key has changed";
        v.key_text = "Publisher key: DIFFERENT from the key associated with this "
                     "application. There is no authenticated key rotation in 0.1.";
        break;
    case PublisherKeyState::Blocked:
        v.severity = AuthenticityView::Severity::Danger;
        v.headline = "Refused — locally blocked";
        v.key_text = "This application is blocked locally.";
        break;
    case PublisherKeyState::RetainedDataConflict:
        v.severity = AuthenticityView::Severity::Danger;
        v.headline = "Refused — data belongs to another key";
        v.key_text = "Retained data for this application belongs to a different "
                     "publisher key.";
        break;
    case PublisherKeyState::TrustUnavailable:
        v.severity = AuthenticityView::Severity::Danger;
        v.headline = "Refused — trust record corrupt";
        v.key_text = "The local trust record is corrupt; refusing (fail closed).";
        break;
    }

    // Authenticity is the gate: an invalid signature is always danger, whatever
    // the local key relationship.
    if (eval.signature != SignatureState::Valid) {
        v.severity = AuthenticityView::Severity::Danger;
        v.headline = "Refused — signature is not valid";
        v.can_proceed = false;
    }
    return v;
}

std::string describe_permission(const std::string& id) {
    const PermissionSpec* spec = find_permission(id);
    return spec != nullptr ? spec->title : id; // unknown ids pass through
}

std::string permission_enforcement(const std::string& id,
                                   const IsolationCapabilities& caps) {
    const PermissionSpec* spec = find_permission(id);
    if (spec == nullptr) return "unknown permission";
    if (caps.status == CapabilityStatus::PolicyUnsupported) {
        return "not enforced on this platform";
    }
    if (spec->baseline == PermissionBaseline::Advisory) {
        return "advisory (recorded, not enforced in 0.1)";
    }
    // Enforceable: currently only "network".
    if (id == "network") {
        return caps.network_namespaces ? "enforced (network namespace)"
                                       : "unavailable on this host";
    }
    return caps.status == CapabilityStatus::Available ? "enforced" : "partial";
}

std::vector<PermissionView>
present_permissions(const std::vector<std::string>& permission_ids,
                    const IsolationCapabilities& caps) {
    std::vector<PermissionView> rows;
    rows.reserve(permission_ids.size());
    for (const std::string& id : permission_ids) {
        rows.push_back({id, describe_permission(id),
                        permission_enforcement(id, caps)});
    }
    return rows;
}

PermissionDeltaView present_permission_delta(const PermissionDelta& delta) {
    PermissionDeltaView v;
    v.expands = delta.expands();
    for (const std::string& id : delta.added) v.added.push_back(describe_permission(id));
    for (const std::string& id : delta.removed) v.removed.push_back(describe_permission(id));
    for (const std::string& id : delta.unchanged) v.unchanged.push_back(describe_permission(id));
    return v;
}

IsolationView present_isolation(const IsolationCapabilities& caps) {
    IsolationView v;
    v.detail = caps.detail;
    switch (caps.status) {
    case CapabilityStatus::Available:
        v.headline = "Baseline isolation is enforced";
        break;
    case CapabilityStatus::PartiallyAvailable:
        v.headline = "Isolation is partially enforced";
        break;
    case CapabilityStatus::Unavailable:
        v.headline = "Isolation is unavailable — launch will be refused";
        break;
    case CapabilityStatus::SetupFailed:
        v.headline = "Isolation setup failed — launch will be refused";
        break;
    case CapabilityStatus::PolicyUnsupported:
        v.headline = "No OS-level isolation on this platform";
        break;
    }

    const bool enforced = caps.status == CapabilityStatus::Available;
    if (caps.status == CapabilityStatus::PolicyUnsupported) {
        v.platform_caveat =
            "This platform provides no runtime containment or cross-process "
            "guarantees; those apply on Linux.";
    } else {
        v.platform_caveat =
            "Linux baseline: a read-only application image, private data/cache/"
            "temp, environment sanitization and (when not granted) network "
            "denial are enforced; file-selection is advisory; display access is "
            "granted ONLY to an application whose manifest declares a GUI "
            "launch mode, and when it is granted the display socket is "
            "genuinely reachable — that is reported, not hidden; a seccomp "
            "syscall filter is not implemented in 0.1.";
    }

    const char* base = enforced ? "enforced" : "not established";
    v.controls = {
        {"Application image read-only", base},
        {"Private data / cache / temp", base},
        {"Environment sanitized", base},
        {"Network denial (when not granted)",
         caps.network_namespaces ? "enforced" : "unavailable"},
        {"File selection (user-files-selected)", "advisory"},
        // Display access is per-launch and DECLARED: a console or service
        // application gets no display socket at all, and a GUI application
        // gets exactly one — not D-Bus, not the home directory, not network.
        {"Display isolation",
         enforced ? "enforced, except for a declared GUI launch mode"
                  : "not established"},
        {"seccomp syscall filter", "not implemented"},
    };
    return v;
}

// ------------------------------------------------------------ signer class

const char* to_string(SignerClass c) {
    switch (c) {
    case SignerClass::UshaVerified: return "usha-verified";
    case SignerClass::OrganizationSigned: return "organization-signed";
    case SignerClass::DeveloperSigned: return "developer-signed";
    case SignerClass::LocallyTrusted: return "locally-trusted";
    case SignerClass::UnknownSigner: return "unknown-signer";
    case SignerClass::InvalidSignature: return "invalid-signature";
    }
    return "unknown-signer";
}

const std::vector<SignerClassInfo>& signer_classes() {
    static const std::vector<SignerClassInfo> kClasses = {
        {SignerClass::UshaVerified, "usha-verified", "Usha Verified",
         "Signed by a recognised high-trust .LEXE signing authority.",
         /*available=*/false,
         "No signing authority exists for this runtime to check against, so "
         "this tier can never be assigned here. It is shown so the scale is "
         "not mistaken for a shorter one."},
        {SignerClass::OrganizationSigned, "organization-signed",
         "Organization Signed",
         "Signed by a key attested to belong to a named organization.",
         /*available=*/false,
         "There is no organizational attestation mechanism in this runtime; an "
         "organization's key is indistinguishable from any other developer "
         "key, and claiming otherwise would be a false assurance."},
        {SignerClass::DeveloperSigned, "developer-signed", "Developer Signed",
         "A valid signature by the key already bound to this application on "
         "this machine. Proves continuity of the signer — not who they are.",
         /*available=*/true, ""},
        {SignerClass::LocallyTrusted, "locally-trusted", "Locally Trusted",
         "A valid signature by a key you explicitly chose to trust on this "
         "machine. Local only: it means nothing on any other machine.",
         /*available=*/true, ""},
        {SignerClass::UnknownSigner, "unknown-signer", "Unknown Signer",
         "A valid signature by a key seen for the first time. The bytes are "
         "consistent with that key; the signer's identity is not established.",
         /*available=*/true, ""},
        {SignerClass::InvalidSignature, "invalid-signature",
         "Invalid Signature",
         "The signature did not verify, is missing or malformed, or the key "
         "presented differs from the one bound to this application.",
         /*available=*/true, ""},
    };
    return kClasses;
}

const SignerClassInfo& signer_class_info(SignerClass c) {
    for (const SignerClassInfo& info : signer_classes()) {
        if (info.signer_class == c) return info;
    }
    return signer_classes().back();
}

SignerClass classify_signer(const TrustEvaluation& eval) {
    // Cryptographic validity first: nothing above "invalid" is reachable
    // without a signature that actually verified.
    if (eval.signature != SignatureState::Valid) {
        return SignerClass::InvalidSignature;
    }
    switch (eval.key_state) {
    case PublisherKeyState::Changed:
    case PublisherKeyState::Blocked:
    case PublisherKeyState::TrustUnavailable:
    case PublisherKeyState::RetainedDataConflict:
        // A valid signature by the WRONG key, or a state we cannot read, is
        // not a trust tier — it is a refusal.
        return SignerClass::InvalidSignature;
    case PublisherKeyState::ExplicitlyTrusted:
        return SignerClass::LocallyTrusted;
    case PublisherKeyState::KnownMatching:
        return SignerClass::DeveloperSigned;
    case PublisherKeyState::FirstSeen:
        break;
    }
    return SignerClass::UnknownSigner;
}

} // namespace lexe::presentation
