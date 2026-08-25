// trust — see trust.hpp. Local trust-on-first-use; no CA, no online identity,
// no remote revocation. Fingerprints derive from canonical key bytes; trust
// records are strictly parsed and atomically written.

#include "core/trust.hpp"

#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <filesystem>
#include <system_error>

namespace lexe {
namespace fs = std::filesystem;

// ------------------------------------------------------------- enum strings

const char* to_string(SignatureState s) {
    switch (s) {
    case SignatureState::Valid:                return "valid";
    case SignatureState::Invalid:              return "invalid";
    case SignatureState::ContentMismatch:      return "content-mismatch";
    case SignatureState::Malformed:            return "malformed";
    case SignatureState::UnsupportedAlgorithm: return "unsupported-algorithm";
    case SignatureState::Missing:              return "missing";
    }
    return "?";
}

const char* to_string(PublisherKeyState s) {
    switch (s) {
    case PublisherKeyState::FirstSeen:            return "first-seen";
    case PublisherKeyState::KnownMatching:        return "known-matching";
    case PublisherKeyState::ExplicitlyTrusted:    return "explicitly-trusted";
    case PublisherKeyState::Changed:              return "changed";
    case PublisherKeyState::Blocked:              return "blocked";
    case PublisherKeyState::RetainedDataConflict: return "retained-data-conflict";
    case PublisherKeyState::TrustUnavailable:     return "trust-unavailable";
    }
    return "?";
}

const char* to_string(TrustDecision d) {
    switch (d) {
    case TrustDecision::AllowFirstInstall:          return "allow-first-install";
    case TrustDecision::AllowKnownUpdate:           return "allow-known-update";
    case TrustDecision::RequireExplicitTrust:       return "require-explicit-trust";
    case TrustDecision::RejectInvalidSignature:     return "reject-invalid-signature";
    case TrustDecision::RejectChangedKey:           return "reject-changed-key";
    case TrustDecision::RejectBlocked:              return "reject-blocked";
    case TrustDecision::RejectCorruptTrust:         return "reject-corrupt-trust";
    case TrustDecision::RejectRetainedDataConflict: return "reject-retained-data-conflict";
    }
    return "?";
}

const char* to_string(KeyRotationState s) {
    switch (s) {
    case KeyRotationState::Unsupported: return "unsupported";
    }
    return "?";
}

const char* to_string(RevocationState s) {
    switch (s) {
    case RevocationState::None:          return "none";
    case RevocationState::LocallyBlocked:return "locally-blocked";
    }
    return "?";
}

SignatureState signature_state_from_report(const VerificationReport& report) {
    if (report.ok()) return SignatureState::Valid;
    const VerificationStage* f = report.first_failure();
    if (f == nullptr) return SignatureState::Invalid;
    // A failed signature stage, or content that no longer matches the signed
    // hashes, is an authenticity failure; earlier structural/manifest/key
    // failures mean the package is malformed.
    if (f->name == "manifest-signature" || f->name == "payload-signature") {
        return SignatureState::Invalid;
    }
    // The signatures verified; a covered file does not match the hashes they
    // sign. Still an authenticity failure, still refused — but reported as what
    // it is.
    if (f->name == "hashes") return SignatureState::ContentMismatch;
    return SignatureState::Malformed;
}

// --------------------------------------------------------------- fingerprint

namespace {

std::string group_hex(const std::string& hex, std::size_t take) {
    std::string up;
    up.reserve(hex.size());
    for (const char c : hex) {
        up.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    if (take != 0 && take < up.size()) up.resize(take);
    std::string out;
    for (std::size_t i = 0; i < up.size(); ++i) {
        if (i != 0 && i % 4 == 0) out.push_back(' ');
        out.push_back(up[i]);
    }
    return out;
}

} // namespace

Fingerprint key_fingerprint(const crypto::PublicKey& key) {
    Fingerprint fp;
    fp.full = crypto::sha256_hex(key.data(), key.size());
    fp.grouped = group_hex(fp.full, 0);
    fp.short_id = group_hex(fp.full, 20);
    return fp;
}

Fingerprint key_fingerprint(const std::string& encoded_key) {
    return key_fingerprint(crypto::decode_public_key(encoded_key));
}

// -------------------------------------------------------------- trust record

std::string TrustRecord::to_json() const {
    nlohmann::ordered_json j;
    j["schemaVersion"] = schema_version;
    j["appId"] = app_id;
    j["publicKey"] = public_key;
    j["fingerprint"] = fingerprint;
    j["firstSeen"] = first_seen;
    j["lastSeen"] = last_seen;
    j["explicitlyTrusted"] = explicitly_trusted;
    j["trustProvenance"] = trust_provenance;
    j["blocked"] = blocked;
    j["blockedAt"] = blocked_at;
    j["priorKeys"] = prior_keys;
    return j.dump(2) + "\n";
}

namespace {

[[noreturn]] void corrupt(const std::string& why) {
    throw CorruptTrustError("trust record: " + why);
}

const nlohmann::json& require(const nlohmann::json& obj, const char* key) {
    const auto it = obj.find(key);
    if (it == obj.end()) corrupt(std::string("missing field \"") + key + "\"");
    return *it;
}

std::string req_string(const nlohmann::json& obj, const char* key) {
    const nlohmann::json& v = require(obj, key);
    if (!v.is_string()) corrupt(std::string("\"") + key + "\" is not a string");
    return v.get<std::string>();
}

bool req_bool(const nlohmann::json& obj, const char* key) {
    const nlohmann::json& v = require(obj, key);
    if (!v.is_boolean()) corrupt(std::string("\"") + key + "\" is not a boolean");
    return v.get<bool>();
}

} // namespace

TrustRecord TrustRecord::from_json(std::string_view text) {
    nlohmann::json j;
    try {
        j = json_strict::parse(text, "trust record", limits::kMaxRecordBytes);
    } catch (const Error& e) {
        // Duplicate keys / malformed / over budget all mean "unusable" here.
        corrupt(e.what());
    }
    if (!j.is_object()) corrupt("top-level value is not an object");

    const nlohmann::json& sv = require(j, "schemaVersion");
    if (!sv.is_number_integer() || sv.get<long long>() != 1) {
        corrupt("unsupported schemaVersion");
    }

    TrustRecord r;
    r.schema_version = 1;
    r.app_id = req_string(j, "appId");
    if (r.app_id.empty() || r.app_id.size() > limits::kMaxIdBytes) {
        corrupt("invalid appId");
    }
    r.public_key = req_string(j, "publicKey");
    r.fingerprint = req_string(j, "fingerprint");
    r.first_seen = req_string(j, "firstSeen");
    r.last_seen = req_string(j, "lastSeen");
    r.explicitly_trusted = req_bool(j, "explicitlyTrusted");
    r.trust_provenance = req_string(j, "trustProvenance");
    r.blocked = req_bool(j, "blocked");
    r.blocked_at = req_string(j, "blockedAt");

    const auto pk = j.find("priorKeys");
    if (pk != j.end()) {
        if (!pk->is_array()) corrupt("\"priorKeys\" is not an array");
        for (const auto& e : *pk) {
            if (!e.is_string()) corrupt("\"priorKeys\" entry is not a string");
            r.prior_keys.push_back(e.get<std::string>());
        }
    }

    if (r.public_key.empty()) {
        // A keyless record is only meaningful as a pure block entry.
        if (!r.blocked) corrupt("record has no bound key and is not a block");
        if (!r.fingerprint.empty()) corrupt("keyless record has a fingerprint");
    } else {
        // Canonical key + matching fingerprint (defeats mixed-case / alternate
        // encodings and a swapped fingerprint).
        crypto::PublicKey decoded;
        try {
            decoded = crypto::decode_public_key(r.public_key);
        } catch (const Error&) {
            corrupt("publicKey is not a valid Ed25519 key");
        }
        if (crypto::encode_public_key(decoded) != r.public_key) {
            corrupt("publicKey is not in canonical encoding");
        }
        if (key_fingerprint(decoded).full != r.fingerprint) {
            corrupt("fingerprint does not match publicKey");
        }
    }
    if (r.explicitly_trusted && r.public_key.empty()) {
        corrupt("explicitly-trusted record has no bound key");
    }
    return r;
}

// ---------------------------------------------------------- trust evaluation

void TrustEvaluation::throw_if_rejected() const {
    const std::string where = " (App ID " + app_id + ")";
    switch (decision) {
    case TrustDecision::AllowFirstInstall:
    case TrustDecision::AllowKnownUpdate:
        return;
    case TrustDecision::RequireExplicitTrust:
        throw TrustError("this key must be explicitly trusted first" + where);
    case TrustDecision::RejectInvalidSignature:
        throw VerificationError("package signature is not valid (" +
                                std::string(to_string(signature)) + ")" + where);
    case TrustDecision::RejectChangedKey: {
        std::string msg = "refusing: signed by a different key than the one "
                          "bound to this App ID" + where;
        if (expected.has_value()) {
            msg += "; expected key " + expected->short_id;
        }
        msg += ", presented key " + presented.short_id +
               ". FORMAT 0.1 has no authenticated key rotation — remove the "
               "application and its data to accept a new publisher, or install "
               "under a different App ID.";
        throw ChangedKeyError(msg);
    }
    case TrustDecision::RejectBlocked:
        throw BlockedKeyError("refusing: this application is locally blocked" +
                              where + " (use `lexe trust unblock` to allow it)");
    case TrustDecision::RejectCorruptTrust:
        throw CorruptTrustError("refusing: the local trust record is corrupt" +
                                where + " (fail closed)");
    case TrustDecision::RejectRetainedDataConflict:
        throw RetainedDataConflict(
            "refusing: persistent data is retained under a different publisher "
            "key" + where + "; purge it to install under this key");
    }
}

// ---------------------------------------------------------------- store

TrustStore::TrustStore(const Paths& paths) : paths_(paths) {}

fs::path TrustStore::record_file(const std::string& id) const {
    return Registry(paths_).trust_record_file(id); // validates id
}

bool TrustStore::exists(const std::string& id) const {
    std::error_code ec;
    return fs::is_regular_file(record_file(id), ec);
}

std::optional<TrustRecord> TrustStore::read(const std::string& id) const {
    const fs::path file = record_file(id);
    std::error_code ec;
    // A trust record must be a real regular file. A symlink here is a path-
    // substitution attempt — fail closed rather than follow it.
    if (fs::is_symlink(file, ec)) {
        corrupt("record path is a symlink");
    }
    if (!fs::is_regular_file(file, ec)) return std::nullopt;
    if (fs::file_size(file, ec) > limits::kMaxRecordBytes) {
        corrupt("record exceeds the size budget");
    }
    TrustRecord r = TrustRecord::from_json(util::slurp_text(file));
    // Substitution defense: a record for a different App ID must never be
    // accepted as this one's.
    if (r.app_id != id) corrupt("record names a different App ID");
    return r;
}

TrustEvaluation TrustStore::evaluate(
    const std::string& id, const crypto::PublicKey& presented_key,
    SignatureState signature,
    const std::optional<std::string>& retained_data_owner) const {
    TrustEvaluation e;
    e.app_id = id;
    e.signature = signature;
    e.presented = key_fingerprint(presented_key);
    e.rotation = KeyRotationState::Unsupported;
    const std::string presented_encoded = crypto::encode_public_key(presented_key);

    std::optional<TrustRecord> rec;
    try {
        rec = read(id);
    } catch (const CorruptTrustError&) {
        e.key_state = PublisherKeyState::TrustUnavailable;
        e.decision = TrustDecision::RejectCorruptTrust;
        e.detail = "the local trust record is corrupt; refusing (fail closed)";
        return e; // corrupt state dominates every other consideration
    }

    // Classify the local key relationship (independent of signature validity),
    // then let an invalid signature override the DECISION at the end.
    if (!rec.has_value()) {
        if (retained_data_owner.has_value() && !retained_data_owner->empty() &&
            *retained_data_owner != presented_encoded) {
            e.key_state = PublisherKeyState::RetainedDataConflict;
            try {
                e.expected = key_fingerprint(*retained_data_owner);
            } catch (const Error&) {
            }
            e.decision = TrustDecision::RejectRetainedDataConflict;
            e.detail = "persistent data is retained under a different "
                       "publisher key for this App ID";
        } else {
            e.key_state = PublisherKeyState::FirstSeen;
            e.decision = TrustDecision::AllowFirstInstall;
            e.detail = "first time this App ID and signing key are seen on this "
                       "machine; the publisher's real-world identity is not "
                       "independently verified";
        }
    } else {
        const TrustRecord& r = *rec;
        if (r.blocked) {
            e.key_state = PublisherKeyState::Blocked;
            e.revocation = RevocationState::LocallyBlocked;
            e.decision = TrustDecision::RejectBlocked;
            if (!r.public_key.empty()) e.expected = key_fingerprint(r.public_key);
            e.detail = "this App ID is locally blocked";
        } else if (r.public_key.empty()) {
            e.key_state = PublisherKeyState::TrustUnavailable;
            e.decision = TrustDecision::RejectCorruptTrust;
            e.detail = "trust record has no bound key";
        } else if (r.public_key != presented_encoded) {
            e.key_state = PublisherKeyState::Changed;
            e.expected = key_fingerprint(r.public_key);
            e.decision = TrustDecision::RejectChangedKey;
            e.detail = "signed by a different key than the one bound to this "
                       "App ID";
        } else {
            e.explicitly_trusted = r.explicitly_trusted;
            e.expected = key_fingerprint(r.public_key);
            e.key_state = r.explicitly_trusted
                              ? PublisherKeyState::ExplicitlyTrusted
                              : PublisherKeyState::KnownMatching;
            e.decision = TrustDecision::AllowKnownUpdate;
            e.detail = r.explicitly_trusted
                           ? "signed by the key you explicitly trusted locally "
                             "for this App ID (a local decision, not external "
                             "identity verification)"
                           : "signed by the same key previously associated with "
                             "this App ID on this machine";
        }
    }

    // Authenticity is the gate: a package whose signature is not valid can never
    // be allowed, whatever the local key relationship says.
    if (signature != SignatureState::Valid) {
        e.decision = TrustDecision::RejectInvalidSignature;
        e.detail = "package signature is not valid (" +
                   std::string(to_string(signature)) + ")";
    }
    return e;
}

void TrustStore::write(const TrustRecord& record) const {
    util::write_atomic(record_file(record.app_id),
                       std::string_view(record.to_json()));
}

void TrustStore::record_accept(const std::string& id,
                               const crypto::PublicKey& key, bool explicit_trust,
                               const std::string& provenance) {
    const std::string enc = crypto::encode_public_key(key);
    std::optional<TrustRecord> existing = read(id); // may throw CorruptTrustError
    const std::string now = util::now_utc_string();

    TrustRecord r;
    if (existing.has_value()) {
        r = *existing;
        if (r.blocked) {
            throw BlockedKeyError("cannot record trust: " + id +
                                  " is locally blocked");
        }
        if (!r.public_key.empty() && r.public_key != enc) {
            throw ChangedKeyError("cannot record trust: " + id +
                                  " is bound to a different key");
        }
        r.public_key = enc;
        r.fingerprint = key_fingerprint(key).full;
        r.last_seen = now;
        if (explicit_trust) {
            r.explicitly_trusted = true;
            r.trust_provenance = provenance;
        }
    } else {
        r.schema_version = 1;
        r.app_id = id;
        r.public_key = enc;
        r.fingerprint = key_fingerprint(key).full;
        r.first_seen = now;
        r.last_seen = now;
        r.explicitly_trusted = explicit_trust;
        r.trust_provenance = explicit_trust ? provenance : "install-accept";
        r.blocked = false;
    }
    write(r);
}

void TrustStore::block(const std::string& id) {
    std::optional<TrustRecord> existing = read(id); // fail closed if corrupt
    const std::string now = util::now_utc_string();
    TrustRecord r;
    if (existing.has_value()) {
        r = *existing;
    } else {
        r.schema_version = 1;
        r.app_id = id;
        r.first_seen = now;
    }
    r.blocked = true;
    r.blocked_at = now;
    r.last_seen = now;
    write(r);
}

void TrustStore::unblock(const std::string& id) {
    std::optional<TrustRecord> existing = read(id);
    if (!existing.has_value()) {
        throw NotFoundError("no local trust record for " + id);
    }
    TrustRecord r = *existing;
    r.blocked = false;
    r.blocked_at.clear();
    r.last_seen = util::now_utc_string();
    // A keyless, non-trusted record is meaningless once unblocked — drop it.
    if (r.public_key.empty() && !r.explicitly_trusted) {
        forget(id);
        return;
    }
    write(r);
}

void TrustStore::forget(const std::string& id) {
    util::remove_recursive(record_file(id));
}

} // namespace lexe
