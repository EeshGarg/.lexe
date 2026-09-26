// launchref — see launchref.hpp (Definitive Architecture §15.1).

#include "lexe/runtime/launchref.hpp"

#include "lexe/base/error.hpp"
#include "lexe/package/package.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/base/util.hpp"
#include "lexe/base/version.hpp"

#include <nlohmann/json.hpp>

#include <system_error>

namespace fs = std::filesystem;

namespace lexe {

namespace {

/// A scratch directory that removes itself — used for the (empty) payload
/// directory and the manifest the writer reads.
class ScratchDir {
public:
    explicit ScratchDir(fs::path dir) : dir_(std::move(dir)) {
        std::error_code ec;
        fs::create_directories(dir_, ec);
    }
    ~ScratchDir() {
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }
    ScratchDir(const ScratchDir&) = delete;
    ScratchDir& operator=(const ScratchDir&) = delete;
    const fs::path& path() const { return dir_; }

private:
    fs::path dir_;
};

/// The manifest of a launch reference. Deliberately minimal: identity, the
/// target application id, and the declared launch presentation (so a frontend
/// can behave correctly before the target's own manifest is read).
std::string launch_manifest_json(const Manifest& app, const std::string& key) {
    nlohmann::ordered_json publisher;
    publisher["name"] = "Local .LEXE launch reference";
    publisher["publicKey"] = key;

    nlohmann::ordered_json launch;
    launch["applicationId"] = app.id;
    launch["mode"] = to_string(app.launch_mode);
    launch["singleInstance"] = app.launch_single_instance;

    nlohmann::ordered_json doc;
    doc["lexeVersion"] = version::kPackageFormat;
    doc["id"] = kLaunchReferenceId;
    doc["name"] = app.name;
    doc["version"] = app.version;
    doc["role"] = "launch";
    doc["publisher"] = std::move(publisher);
    doc["launch"] = std::move(launch);
    return doc.dump(2) + "\n";
}

} // namespace

crypto::KeyPair local_launch_key(const Paths& paths) {
    const fs::path file = paths.keys_dir() / "local-root.json";
    std::error_code ec;
    if (fs::is_regular_file(file, ec)) {
        return crypto::read_keyfile(file);
    }
    fs::create_directories(paths.keys_dir(), ec);
    if (ec) {
        throw Error("launch reference: cannot create the local key directory: " +
                    paths.keys_dir().string());
    }
#ifndef _WIN32
    // The key directory itself is owner-only: a launch reference signed by
    // this key is trusted locally, so the key must not be world-readable.
    fs::permissions(paths.keys_dir(),
                    fs::perms::owner_all, fs::perm_options::replace, ec);
#endif
    const crypto::KeyPair key = crypto::generate_keypair();
    crypto::write_keyfile(file, key); // 0600 on POSIX
    return key;
}

std::string local_launch_key_string(const Paths& paths) {
    return crypto::encode_public_key(local_launch_key(paths).public_key);
}

fs::path launch_reference_path(const Paths& paths, const std::string& id) {
    validate_app_id(id, "launch reference");
    return paths.launch_dir() / (id + ".lexe");
}

fs::path write_launch_reference(const Paths& paths, const Manifest& app_manifest,
                                const fs::path& out_file) {
    if (app_manifest.role != PackageRole::Application) {
        throw Error("launch reference: can only be generated for an "
                    "installable application, not for another launch "
                    "reference");
    }
    validate_app_id(app_manifest.id, "launch reference");

    const crypto::KeyPair key = local_launch_key(paths);

    // Build the reference in a scratch tree, then hand it to the ordinary
    // PackageWriter: a launch reference is a REAL .lexe, produced by the same
    // code path and verifiable by the same pipeline as any other package.
    const ScratchDir scratch(paths.cache_dir() / "launchref-work" /
                             app_manifest.id);
    const fs::path payload_dir = scratch.path() / "payload"; // stays empty
    std::error_code ec;
    fs::create_directories(payload_dir, ec);
    const fs::path manifest_file = scratch.path() / "lexe.json";
    util::spit(manifest_file,
               std::string_view(launch_manifest_json(
                   app_manifest, crypto::encode_public_key(key.public_key))));

    PackageWriter::Inputs inputs;
    inputs.payload_dir = payload_dir;
    inputs.manifest_file = manifest_file;
    inputs.allow_empty_payload = true; // §15.1: a reference carries no payload

    fs::create_directories(out_file.parent_path(), ec);
    PackageWriter::write(inputs, key, out_file);
    return out_file;
}

fs::path create_launch_reference(const Paths& paths,
                                 const Manifest& app_manifest) {
    return write_launch_reference(paths, app_manifest,
                                  launch_reference_path(paths, app_manifest.id));
}

} // namespace lexe
