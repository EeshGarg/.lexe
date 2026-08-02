#pragma once
// trust — the typed LOCAL publisher-trust model (runtime-trust WS3). It keeps
// three concerns strictly separate and never collapses them into a single
// "verified" / "trusted" / "safe" boolean:
//
//   * package AUTHENTICITY  — is the signature cryptographically valid, and by
//                             which key (the FORMAT-0.1 §6 pipeline, verify.hpp)
//   * local publisher TRUST — has THIS (App ID, key) been seen / accepted /
//                             blocked on THIS machine (this module)
//   * runtime ENFORCEMENT    — which controls the backend actually establishes
//                             at launch (isolation.hpp)
//
// This is trust-on-first-use, and LOCAL only: there is no certificate authority,
// no online identity service, no transparency log and no remote revocation. A
// cryptographically valid signature proves the package is consistent with a key
// — NOT the publisher's real-world identity, name, ownership of a website, or
// safety. First-seen is never treated as externally verified.

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/paths.hpp"
#include "core/verify.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace lexe {

// ---------------------------------------------------------- authenticity

/// The signature dimension, derived from the §6 verification pipeline. Says
/// nothing about who the publisher is — only whether the bytes are consistent
/// with the presented key.
enum class SignatureState {
    Valid,                // every signature verified over the exact signed bytes
    Invalid,              // a signature did not verify, or signed content changed
    Malformed,            // structure / manifest / key material malformed
    UnsupportedAlgorithm, // signing algorithm is not the supported Ed25519
    Missing,              // no signature present (0.1 forbids unsigned packages)
};
const char* to_string(SignatureState s);

/// Map a verification report to the signature dimension.
SignatureState signature_state_from_report(const VerificationReport& report);

// ------------------------------------------------------ local publisher key

/// The local trust relationship between an App ID and the key presenting itself.
enum class PublisherKeyState {
    FirstSeen,            // no local trust record for this App ID yet
    KnownMatching,        // a record exists and the presented key matches it
    ExplicitlyTrusted,    // KnownMatching AND the user explicitly trusted the key
    Changed,              // a record exists and the presented key is DIFFERENT
    Blocked,              // this App ID / key is locally blocked
    RetainedDataConflict, // no record, but data is retained under another key
    TrustUnavailable,     // trust record present but corrupt/unreadable (closed)
};
const char* to_string(PublisherKeyState s);

/// The typed decision. Frontends switch on this, never on message text.
enum class TrustDecision {
    AllowFirstInstall,          // valid sig + first-seen: needs explicit consent
    AllowKnownUpdate,           // known matching key: normal update policy applies
    RequireExplicitTrust,       // policy demands an explicit trust step first
    RejectInvalidSignature,     // authenticity failed
    RejectChangedKey,           // different key than the one bound to this App ID
    RejectBlocked,              // locally blocked
    RejectCorruptTrust,         // trust record corrupt — fail closed
    RejectRetainedDataConflict, // retained data belongs to a different key
};
const char* to_string(TrustDecision d);

/// FORMAT 0.1 has no authenticated key-rotation mechanism, so a changed key is
/// always rejected. The enum exists so the state is named, not implied.
enum class KeyRotationState {
    Unsupported, // no signed old-key authorization of a new key exists in 0.1
};
const char* to_string(KeyRotationState s);

/// Local blocking is the only revocation-like control. It is NOT a global or
/// real-world revocation and must never be presented as one.
enum class RevocationState {
    None,
    LocallyBlocked,
};
const char* to_string(RevocationState s);

// -------------------------------------------------------------- fingerprint

/// A canonical, human-readable fingerprint of a public key. Derived from the
/// exact canonical key bytes (SHA-256 of the raw 32-byte Ed25519 public key), so
/// it is stable across platforms and cannot be forged from the free-form
/// publisher display string.
struct Fingerprint {
    std::string full;    // 64 lowercase hex chars (the authoritative value)
    std::string grouped; // the full value, uppercase, in space-separated 4s
    std::string short_id;// first 20 uppercase hex, grouped — for compact display
};
Fingerprint key_fingerprint(const crypto::PublicKey& key);
/// Fingerprint of an encoded "ed25519:…" key string (decodes first; throws
/// VerificationError on a malformed encoding).
Fingerprint key_fingerprint(const std::string& encoded_key);

// ---------------------------------------------------------- trust record

/// One local trust record (`<LEXE_HOME>/trust/<id>.json`). Holds only what
/// enforcement and audit need — never a private key.
struct TrustRecord {
    int schema_version = 1;
    std::string app_id;
    std::string public_key;   // canonical "ed25519:…"; empty ONLY for a pure block
    std::string fingerprint;  // full fingerprint of public_key ("" iff no key)
    std::string first_seen;   // RFC 3339 UTC
    std::string last_seen;    // RFC 3339 UTC
    bool explicitly_trusted = false;
    std::string trust_provenance; // e.g. "install-consent", "trust-command"
    bool blocked = false;
    std::string blocked_at;       // RFC 3339 UTC ("" when not blocked)
    std::vector<std::string> prior_keys; // audit evidence only (not rotation)

    std::string to_json() const;
    /// Strict parse (duplicate-key rejection, byte budget, canonical key,
    /// fingerprint match). Throws CorruptTrustError on any inconsistency.
    static TrustRecord from_json(std::string_view text);
};

/// The full evaluation of an incoming package for one App ID. Every dimension is
/// explicit; `decision` is what callers act on.
struct TrustEvaluation {
    std::string app_id;
    SignatureState signature = SignatureState::Missing;
    PublisherKeyState key_state = PublisherKeyState::TrustUnavailable;
    TrustDecision decision = TrustDecision::RejectCorruptTrust;
    RevocationState revocation = RevocationState::None;
    KeyRotationState rotation = KeyRotationState::Unsupported;
    Fingerprint presented;                 // fingerprint of the presented key
    std::optional<Fingerprint> expected;   // bound key (Changed / Known)
    bool explicitly_trusted = false;       // the bound key was explicitly trusted
    std::string detail;                    // human-readable, non-authoritative

    bool allowed() const {
        return decision == TrustDecision::AllowFirstInstall ||
               decision == TrustDecision::AllowKnownUpdate;
    }
    bool needs_first_install_consent() const {
        return decision == TrustDecision::AllowFirstInstall;
    }
    /// Throw the typed error matching a rejecting decision (no-op when allowed).
    void throw_if_rejected() const;
};

/// Reads, evaluates and mutates local trust records. Pure file I/O — it does NOT
/// take the per-app mutation lock itself; callers that mutate (installer, the
/// `lexe trust` commands) hold that lock so trust writes serialize with other
/// mutations of the same App ID (WS9).
class TrustStore {
public:
    explicit TrustStore(const Paths& paths);

    std::filesystem::path record_file(const std::string& id) const;
    bool exists(const std::string& id) const;

    /// Read the record for `id`, or std::nullopt when none exists. Throws
    /// CorruptTrustError when a record is present but unreadable, over budget, a
    /// symlink, internally inconsistent, or names a different App ID.
    std::optional<TrustRecord> read(const std::string& id) const;

    /// Evaluate authenticity + local trust. `retained_data_owner` is the
    /// data-owner marker's key if persistent data is retained (WS8), else empty.
    TrustEvaluation evaluate(
        const std::string& id, const crypto::PublicKey& presented_key,
        SignatureState signature,
        const std::optional<std::string>& retained_data_owner) const;

    /// Persist the (App ID, key) binding after a SUCCESSFUL commit. Idempotent:
    /// refreshes last_seen, keeps first_seen, and OR-s in explicit trust. Throws
    /// CorruptTrustError if an existing record is unreadable, ChangedKeyError if
    /// it binds a different (non-blocked) key.
    void record_accept(const std::string& id, const crypto::PublicKey& key,
                       bool explicit_trust, const std::string& provenance);

    /// Locally block the App ID (creates a keyless block record if none exists).
    void block(const std::string& id);
    /// Remove a local block. Throws NotFoundError when there is no record.
    void unblock(const std::string& id);
    /// Delete the trust record entirely (caller enforces any safety policy).
    void forget(const std::string& id);

private:
    void write(const TrustRecord& record) const; // atomic
    Paths paths_;
};

} // namespace lexe
