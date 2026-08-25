// presentation — see presentation.hpp. Pure, frontend-neutral formatting.

#include "core/presentation.hpp"

#include <algorithm>
#include <cstdio>
#include <iterator>

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
    case SignatureState::ContentMismatch:
        return "valid, but the package contents do not match it";
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
        v.headline = eval.signature == SignatureState::ContentMismatch
                         ? "Refused — the contents do not match the signature"
                         : "Refused — signature is not valid";
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
            "denial are enforced; file-selection is advisory; GUI forwarding is "
            "unavailable; a seccomp syscall filter is not implemented in 0.1.";
    }

    const char* base = enforced ? "enforced" : "not established";
    v.controls = {
        {"Application image read-only", base},
        {"Private data / cache / temp", base},
        {"Environment sanitized", base},
        {"Network denial (when not granted)",
         caps.network_namespaces ? "enforced" : "unavailable"},
        {"File selection (user-files-selected)", "advisory"},
        {"GUI forwarding", "unavailable"},
        {"seccomp syscall filter", "not implemented"},
    };
    return v;
}

// ------------------------------------------------- package display fields

std::string format_size(std::uint64_t bytes) {
    static const char* const kUnits[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1000.0 && unit + 1 < std::size(kUnits)) {
        value /= 1000.0;
        ++unit;
    }
    char buf[64];
    if (unit == 0) {
        std::snprintf(buf, sizeof(buf), "%llu B",
                      static_cast<unsigned long long>(bytes));
    } else if (value < 10.0) {
        std::snprintf(buf, sizeof(buf), "%.1f %s", value, kUnits[unit]);
    } else {
        std::snprintf(buf, sizeof(buf), "%.0f %s", value, kUnits[unit]);
    }
    return buf;
}

std::string application_type_line(const std::string& application_type,
                                  const std::vector<std::string>& architectures,
                                  const std::string& host_arch) {
    const std::string type =
        application_type == "native" ? "Native Linux" : application_type;
    // The host architecture alone when this package runs here; otherwise name
    // every architecture it does offer, so "why not here" is visible.
    if (std::find(architectures.begin(), architectures.end(), host_arch) !=
        architectures.end()) {
        return type + " — " + host_arch;
    }
    std::string joined;
    for (const std::string& a : architectures) {
        if (!joined.empty()) joined += ", ";
        joined += a;
    }
    return type + " — " +
           (joined.empty() ? std::string("unknown architecture") : joined);
}

std::string install_scope_line(const std::string& scope) {
    if (scope == "user") return "Current user only";
    if (scope == "system") return "All users (system-wide)";
    return scope;
}

std::string updates_line(bool enabled, const std::string& manifest_url,
                         const std::string& channel) {
    if (!enabled || manifest_url.empty()) return "No automatic updates";
    return "Automatically check " + manifest_url + " (channel: " + channel + ")";
}

std::string source_line(const std::string& install_mode,
                        const std::string& package_filename) {
    if (install_mode == "bundled") {
        return "Bundled package — all application files are contained in " +
               package_filename;
    }
    return install_mode + " (unsupported in Lexe 0.1)";
}

std::string local_trust_label(const std::string& state) {
    if (state == "blocked") return "blocked locally";
    if (state == "explicitly-trusted") return "explicitly trusted locally";
    if (state == "corrupt") return "CORRUPT (fail closed)";
    if (state == "known") return "known key, accepted for this App ID";
    return "first-seen (identity not verified)";
}

std::string install_size_line(std::uint64_t estimated_size,
                              std::uint64_t payload_bytes) {
    const std::uint64_t size = estimated_size > 0 ? estimated_size : payload_bytes;
    return size > 0 ? format_size(size) : std::string();
}

} // namespace lexe::presentation
