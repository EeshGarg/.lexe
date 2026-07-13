#pragma once
// manifest — the `lexe.json` application manifest (FORMAT-0.1 §5). A plain
// value struct plus strict parse/serialize. Unknown JSON fields are ignored
// (forward compatibility); missing/invalid REQUIRED fields are rejected.

#include "core/crypto.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace lexe {

/// One `integration.fileAssociations[]` element (FORMAT-0.1 §5 optional).
struct FileAssociation {
    std::string extension; // e.g. ".example"
    std::string mime_type; // e.g. "application/x-example"
};

/// Mirrors FORMAT-0.1 §5. Optional fields carry their documented defaults.
struct Manifest {
    // --- required (§5 table) ---
    std::string lexe_version;         // MUST be "0.1"
    std::string id;                   // reverse-DNS, ≤255 chars
    std::string name;                 // non-empty
    std::string version;              // non-empty, ordered per §8
    std::string publisher_name;       // publisher.name, non-empty
    std::string publisher_public_key; // publisher.publicKey, "ed25519:…" (§4)
    std::string application_type;     // MUST be "native" in 0.1
    std::vector<std::string> architectures;   // non-empty; x86_64 / aarch64
    std::string entrypoint_executable;        // relative path inside payload/
    std::string install_mode;                 // MUST be "bundled" in 0.1

    // --- optional with defaults (§5) ---
    std::vector<std::string> entrypoint_arguments; // default []
    std::string publisher_website;                 // default ""
    std::string install_scope = "user";
    std::uint64_t install_estimated_size = 0;      // 0 = not provided
    std::vector<std::string> permissions;          // informational in 0.1

    // updates (§7); disabled when the block is absent
    bool updates_enabled = false;
    std::string updates_channel = "stable";
    std::string updates_manifest_url;              // https:// (tests: file://)
    bool updates_allow_source_change = true;

    // integration (§9)
    bool integration_desktop_entry = true;
    std::vector<std::string> categories;
    std::vector<FileAssociation> file_associations;

    /// Parse and validate the exact bytes of a stored `lexe.json` entry.
    /// Throws VerificationError describing the first violated §5 constraint.
    static Manifest parse(const std::vector<std::uint8_t>& bytes);
    /// Same, from text (convenience for tools/tests).
    static Manifest parse(std::string_view json_text);

    /// Serialize back to JSON text (used by `lexe pack` tooling and the
    /// registry's manifest.json copy). Not byte-identical to the input.
    std::string to_json() const;

    /// Decode publisher_public_key per FORMAT-0.1 §4 (throws VerificationError).
    crypto::PublicKey decoded_public_key() const;
};

} // namespace lexe
