// permissions — the frozen 0.1 permission vocabulary and the ONE path that
// parses, validates, normalizes, digests and diffs a package's requested
// permissions (runtime-trust milestone WS2/WS5). A permission is never accepted
// merely because the installer can display its text: unknown, duplicate and
// conflicting permissions are rejected here, before consent or install.
//
// Truthfulness: each permission carries a BASELINE enforcement class describing
// what the platform CAN do, not what is active. Whether a permission is
// actually enforced at runtime depends on the isolation backend detected at
// launch (see the launcher / isolation modules); this module never claims a
// permission is enforced.

#pragma once

#include <string>
#include <vector>

namespace lexe {

/// What the platform is capable of doing about a permission. The ACTUAL runtime
/// state (enforced / partially / advisory / unsupported) is decided by the
/// isolation backend at launch — this is only the ceiling.
enum class PermissionBaseline {
    Advisory,    // displayed and recorded, but 0.1 has no mechanism to enforce it
    Enforceable, // an available isolation backend CAN enforce it (e.g. deny it)
};

/// One entry of the frozen vocabulary (runtime-trust WS2).
struct PermissionSpec {
    std::string id;          // stable manifest identifier
    std::string title;       // short human-readable installer label
    std::string governs;     // the exact resource/operation governed
    PermissionBaseline baseline;
    /// Adding this permission on an update requires fresh explicit consent
    /// (true for every capability grant in 0.1).
    bool addition_requires_consent = true;
};

/// The frozen 0.1 vocabulary. Anything not here is "unknown" and rejected.
const std::vector<PermissionSpec>& permission_vocabulary();

/// Look up a permission by id, or nullptr when it is not in the vocabulary.
const PermissionSpec* find_permission(const std::string& id);

/// A validated, normalized permission set: the known ids in canonical (sorted,
/// unique) order plus a stable digest over that canonical form. Two manifests
/// that request the same capabilities in any order produce the same digest.
struct NormalizedPermissions {
    std::vector<std::string> ids; // sorted, unique, all in the vocabulary
    std::string digest;           // "sha256:" + hex over the canonical form
};

/// Parse and normalize raw manifest permission strings. Throws
/// VerificationError on an unknown, duplicate, or conflicting permission (a
/// package must not smuggle an expansion via reordering, aliases, or dupes).
NormalizedPermissions normalize_permissions(const std::vector<std::string>& raw);

/// Rebuild a NormalizedPermissions from an already-normalized id list (e.g. the
/// approved set stored in the installation record). Still validates the ids and
/// recomputes the digest, so a tampered record cannot forge a digest.
NormalizedPermissions normalized_from_ids(const std::vector<std::string>& ids);

/// The permission change from an installed `approved` set to a `candidate` set.
struct PermissionDelta {
    std::vector<std::string> added;     // in candidate, not approved (expansion)
    std::vector<std::string> removed;   // in approved, not candidate
    std::vector<std::string> unchanged; // in both
    /// True when the candidate grants at least one capability the user has not
    /// already approved — the case that requires explicit consent.
    bool expands() const { return !added.empty(); }
};

PermissionDelta permission_delta(const NormalizedPermissions& approved,
                                 const NormalizedPermissions& candidate);

} // namespace lexe
