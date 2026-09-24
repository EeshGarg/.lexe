#pragma once
// launchref — first-class `.lexe` LAUNCH REFERENCES (Definitive Architecture
// §15.1 "Launch artifact + persistence contract").
//
// The alpha installed the executable successfully but left the raw ELF as the
// thing the desktop had to understand. The definitive architecture keeps the
// payload private and gives the user a real .LEXE artifact instead:
//
//   what the user sees              what .LEXE keeps private
//   ------------------              ------------------------
//   App.lexe / install.lexe  ---->  signed package contents
//   run.lexe                 ---->  installed app ID + launch role
//   application-menu icon    ---->  lexe run <application-id>
//
// A launch reference is a REAL .lexe: same container, same MIME type, same
// verification pipeline. What differs is the signed manifest's `role`, which
// is "launch" and carries `launch.applicationId` instead of a payload. The
// handler reads the role and performs the correct operation (§15.1).
//
// Launch references are generated ON THIS MACHINE for applications installed
// on it, so they are signed by a MACHINE-LOCAL key — the "Locally Trusted"
// signer class of §4, never a publisher key and never a substitute for one.
// The local key lives outside every package-controlled path and is created
// with owner-only permissions on first use.

#include "core/crypto.hpp"
#include "core/manifest.hpp"
#include "core/paths.hpp"

#include <filesystem>
#include <string>

namespace lexe {

/// The App ID every launch reference carries in its own `id` field. It is a
/// fixed identity for "a .LEXE launch reference", deliberately NOT the target
/// application's id: the trust store binds ids to keys, and a launch reference
/// must never bind a real application's id to the machine-local key.
inline constexpr const char* kLaunchReferenceId = "org.lexe.launch";

/// Load (or create on first use) the machine-local signing key used for launch
/// references. Stored at `<home>/keys/local-root.json` with owner-only
/// permissions. Throws Error when it cannot be created or read.
crypto::KeyPair local_launch_key(const Paths& paths);

/// The public key string ("ed25519:…") of the machine-local launch key.
std::string local_launch_key_string(const Paths& paths);

/// Where the canonical launch reference for `id` lives:
/// `<home>/launch/<application-id>.lexe` (§15.1).
std::filesystem::path launch_reference_path(const Paths& paths,
                                            const std::string& id);

/// Write a launch reference for the installed application described by
/// `app_manifest` to `out_file`. The result is a fully signed, fully
/// verifiable `.lexe` whose role is "launch". Returns `out_file`.
std::filesystem::path write_launch_reference(const Paths& paths,
                                             const Manifest& app_manifest,
                                             const std::filesystem::path& out_file);

/// Create/refresh the canonical launch reference for an installed application
/// (`<home>/launch/<id>.lexe`). Returns its path.
std::filesystem::path create_launch_reference(const Paths& paths,
                                              const Manifest& app_manifest);

/// True when `manifest` is a launch reference.
inline bool is_launch_reference(const Manifest& manifest) {
    return manifest.role == PackageRole::Launch;
}

} // namespace lexe
