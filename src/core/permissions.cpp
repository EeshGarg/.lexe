// permissions — see permissions.hpp.

#include "core/permissions.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"

#include <algorithm>
#include <set>

namespace lexe {

const std::vector<PermissionSpec>& permission_vocabulary() {
    // The frozen 0.1 vocabulary. Keep this SMALL and truthful — a permission is
    // only listed when its semantics and enforcement ceiling are defined.
    static const std::vector<PermissionSpec> kVocabulary = {
        {"network", "Network access",
         "Outbound and inbound network sockets",
         PermissionBaseline::Enforceable, true},
        {"user-files-selected", "Access to files you choose",
         "Files the user explicitly selects at runtime (no ambient file access)",
         PermissionBaseline::Advisory, true},
    };
    return kVocabulary;
}

const PermissionSpec* find_permission(const std::string& id) {
    for (const PermissionSpec& spec : permission_vocabulary()) {
        if (spec.id == id) return &spec;
    }
    return nullptr;
}

namespace {

/// Canonical digest over a sorted, unique id list. The version tag keeps digests
/// from colliding across future vocabulary/format revisions.
std::string digest_of(const std::vector<std::string>& sorted_ids) {
    std::string canonical = "lexe-permset-v1";
    for (const std::string& id : sorted_ids) {
        canonical.push_back('\n');
        canonical += id;
    }
    const std::vector<std::uint8_t> bytes(canonical.begin(), canonical.end());
    return "sha256:" + crypto::sha256_hex(bytes);
}

/// Shared validation: every id known, no duplicates, no conflicts. Returns the
/// sorted unique id list.
std::vector<std::string> validate_and_sort(const std::vector<std::string>& raw) {
    std::set<std::string> seen;
    std::vector<std::string> ids;
    for (const std::string& id : raw) {
        if (find_permission(id) == nullptr) {
            throw VerificationError("unknown permission \"" + id +
                                    "\" (not in the 0.1 vocabulary)");
        }
        if (!seen.insert(id).second) {
            throw VerificationError("duplicate permission \"" + id + "\"");
        }
        ids.push_back(id);
    }
    // No conflicting-permission pairs exist in the 0.1 vocabulary; the check
    // point stays here so the rule is enforced the moment one is defined.
    std::sort(ids.begin(), ids.end());
    return ids;
}

} // namespace

NormalizedPermissions
normalize_permissions(const std::vector<std::string>& raw) {
    NormalizedPermissions out;
    out.ids = validate_and_sort(raw);
    out.digest = digest_of(out.ids);
    return out;
}

NormalizedPermissions
normalized_from_ids(const std::vector<std::string>& ids) {
    return normalize_permissions(ids);
}

PermissionDelta permission_delta(const NormalizedPermissions& approved,
                                 const NormalizedPermissions& candidate) {
    const std::set<std::string> a(approved.ids.begin(), approved.ids.end());
    const std::set<std::string> c(candidate.ids.begin(), candidate.ids.end());
    PermissionDelta delta;
    for (const std::string& id : candidate.ids) {
        (a.count(id) ? delta.unchanged : delta.added).push_back(id);
    }
    for (const std::string& id : approved.ids) {
        if (c.count(id) == 0) delta.removed.push_back(id);
    }
    return delta;
}

} // namespace lexe
