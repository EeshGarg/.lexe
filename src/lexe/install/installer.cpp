// installer — userspace install / uninstall / rollback / repair (SPEC
// "Standard User Flow", FORMAT-0.1 §6 verification, §9 installed layout).
//
// Trust rules implemented here:
//  * nothing is extracted or recorded before the full §6 pipeline passes
//    (signature-before-parse discipline, security invariant #2);
//  * the publisher key pinned in installation.json is the update trust
//    anchor (§7.1) — a package for an already-installed id signed with a
//    different key is a hard error, never a silent takeover;
//  * payload lands in versions/<v>/ via a staging directory so a failed
//    extraction cannot leave a half-written version behind;
//  * the exact lexe.json and hashes.json bytes of every installed version
//    are kept under apps/<id>/meta/<v>/ — the hash source for repair and
//    the restore source for rollback — with the active version's copies at
//    apps/<id>/manifest.json and apps/<id>/hashes.json (FORMAT-0.1 §9).

#include "lexe/install/installer.hpp"
#include "lexe/state/appstate.hpp"
#include "lexe/base/identity.hpp"

#include "lexe/package/crypto.hpp"
#include "lexe/analysis/depengine.hpp"
#include "lexe/integration/desktop.hpp"
#include "lexe/diagnostics/diagnostics.hpp"
#include "lexe/integration/integration.hpp"
#include "lexe/base/error.hpp"
#include "lexe/base/fault.hpp"
#include "lexe/runtime/hostbuild.hpp"
#include "lexe/base/json_strict.hpp"
#include "lexe/base/limits.hpp"
#include "lexe/package/package.hpp"
#include "lexe/sandbox/permissions.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/install/transaction.hpp"
#include "lexe/verify/trust.hpp"
#include "lexe/base/util.hpp"
#include "lexe/verify/verify.hpp"
#include "lexe/base/versioncmp.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace lexe {

namespace {

constexpr std::string_view kPayloadPrefix = "payload/";

/// apps/<id>/meta/<version>/ — the per-version store of the exact lexe.json
/// and hashes.json bytes of an installed version.
fs::path meta_dir(const fs::path& app_dir, const std::string& version) {
    return app_dir / "meta" / version;
}

/// Turn a hashes.json key ("payload/<rel>") into a relative path that is
/// safe to join under the version directory. Returns nullopt for keys
/// outside payload/ (icons/, metadata/ — those are not installed files).
/// The stored hashes.json copy is plain state on disk, not a signed package
/// entry, so its keys are NOT trusted for path building: anything that could
/// escape the version dir throws (security invariant #1).
std::optional<fs::path> payload_relative(const std::string& key) {
    if (key.compare(0, kPayloadPrefix.size(), kPayloadPrefix) != 0) {
        return std::nullopt;
    }
    const std::string rel = key.substr(kPayloadPrefix.size());
    bool ok = !rel.empty() && rel.find('\\') == std::string::npos &&
              rel.find(':') == std::string::npos &&
              rel.find('\0') == std::string::npos;
    std::size_t start = 0;
    while (ok) {
        const std::size_t slash = rel.find('/', start);
        const std::size_t end = (slash == std::string::npos) ? rel.size() : slash;
        const std::string_view segment =
            std::string_view(rel).substr(start, end - start);
        ok = !segment.empty() && segment != "." && segment != "..";
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    if (!ok) {
        throw Error("recorded hashes contain an unsafe payload path: \"" + key +
                    "\"");
    }
    return fs::path(rel);
}

/// One payload file of the stored hashes.json copy.
struct PayloadHash {
    std::string key;    // full hashes.json key ("payload/…")
    fs::path relative;  // safe path under versions/<v>/
    std::string digest; // expected lowercase-hex SHA-256 (FORMAT-0.1 §3)
};

/// Payload entries of a stored hashes.json copy. Throws Error on malformed
/// contents. Keys come back sorted (nlohmann object iteration order).
std::vector<PayloadHash> load_payload_hashes(const fs::path& hashes_file) {
    // Strict parse (HARDENING.md §E): the installed hashes.json is the source of
    // truth for repair; reject duplicate keys rather than silently collapse.
    const nlohmann::json doc = json_strict::parse(
        util::slurp_text(hashes_file), "installed hashes.json",
        limits::kMaxHashesBytes);
    if (!doc.is_object()) {
        throw Error("recorded hashes are malformed: " + hashes_file.string());
    }
    const auto files = doc.find("files");
    if (files == doc.end() || !files->is_object()) {
        throw Error("recorded hashes are malformed (no \"files\" object): " +
                    hashes_file.string());
    }
    std::vector<PayloadHash> entries;
    for (const auto& item : files->items()) {
        const std::optional<fs::path> relative = payload_relative(item.key());
        if (!relative.has_value()) continue; // icons/, metadata/: not installed
        if (!item.value().is_string()) {
            throw Error("recorded hashes are malformed: digest for \"" +
                        item.key() + "\" is not a string");
        }
        entries.push_back(
            {item.key(), *relative, item.value().get<std::string>()});
    }
    return entries;
}

/// Re-hash installed payload files against the recorded digests; returns the
/// entries that are missing or mismatch.
std::vector<PayloadHash>
corrupt_payload_files(const fs::path& version_dir,
                      const std::vector<PayloadHash>& expected) {
    std::vector<PayloadHash> bad;
    for (const PayloadHash& entry : expected) {
        const fs::path file = version_dir / entry.relative;
        std::error_code ec;
        if (!fs::is_regular_file(file, ec) ||
            crypto::sha256_file_hex(file) != entry.digest) {
            bad.push_back(entry);
        }
    }
    return bad;
}

std::vector<std::string> keys_of(const std::vector<PayloadHash>& entries) {
    std::vector<std::string> keys;
    keys.reserve(entries.size());
    for (const PayloadHash& entry : entries) keys.push_back(entry.key);
    return keys;
}

/// Staged validation (HARDENING.md §A step 5): the freshly extracted tree at
/// `version_dir` must match the signed hashes.json that was staged beside it,
/// BEFORE it is promoted into place. Throws VerificationError on any mismatch.
void validate_staged_tree(const fs::path& version_dir,
                          const fs::path& staged_hashes) {
    const std::vector<PayloadHash> expected = load_payload_hashes(staged_hashes);
    const std::vector<PayloadHash> corrupt =
        corrupt_payload_files(version_dir, expected);
    if (!corrupt.empty()) {
        throw VerificationError(
            "staged installation failed validation (" +
            std::to_string(corrupt.size()) +
            " payload file(s) missing or mismatched): " +
            keys_of(corrupt).front() + (corrupt.size() > 1 ? ", …" : ""));
    }
}

/// Compile a staged portable payload for this host (Definitive Architecture
/// §5/§7) and record what the build produced.
///
/// Everything happens inside the STAGING tree, so every way this can end —
/// refused for want of approval, no sandbox to build in, the build failed, the
/// build produced something that is not a host-ISA executable — leaves the
/// previously installed version exactly where it was.
///
/// Each failure also leaves a structured §9 record carrying the build's OWN
/// output. A failed compile without the compiler diagnostics is not a
/// diagnosis, and the person installing may have no terminal to have seen them
/// on.
/// Resolve `version_dir / relative` and refuse it if it escapes `version_dir`.
///
/// Repair validates the payload KEY -- `payload_relative()` rejects `..`,
/// backslashes, `:`, NUL and empty segments -- and then never resolved the
/// DESTINATION. So a symlink already inside the version directory redirected the
/// write: with `versions/1.0.0/lib -> /tmp/escape` in place, repairing
/// `payload/lib/data.dat` created `/tmp/escape/data.dat` and reported `rc=0,
/// Repaired 1 file(s)`.
///
/// The galling part is that the guard existed one function away and was simply
/// not applied: `extract_payload` resolves every destination with
/// `weakly_canonical` + `lexically_relative` (security invariant #1), which is
/// what protects the staging tree two lines above the copy that was not
/// protected.
///
/// What the primitive actually was, stated precisely rather than inflated: the
/// content written is AUTHENTIC package bytes -- the package is re-verified for
/// id, version and pinned publisher key before anything is copied, and that
/// check holds -- so it created or overwrote a file at an arbitrary path with
/// content drawn from a verified package. It also needed a symlink pre-planted
/// inside the version directory, and whoever can do that can already write
/// there.
///
/// Fixed anyway, for the reason `remove_app`'s containment was: it is a confused
/// deputy that turns "can write inside this application's version directory"
/// into "write somewhere else entirely", it is triggered by the command a user
/// runs BECAUSE something is already wrong, and it reported success. Malice is
/// not required either -- a user or a backup tool that replaced a bulky payload
/// subdirectory with a symlink gets silent out-of-tree writes on the next repair.
///
/// Returns nullopt when the destination escapes; the caller reports that rather
/// than skipping quietly, because a payload path resolving outside the version
/// directory is itself a finding.
std::optional<fs::path> contained_destination(const fs::path& version_dir,
                                              const fs::path& relative) {
    std::error_code ec;
    const fs::path root = fs::weakly_canonical(version_dir, ec);
    const fs::path base = ec ? version_dir : root;

    const fs::path candidate = base / relative;
    std::error_code resolve_ec;
    const fs::path resolved = fs::weakly_canonical(candidate, resolve_ec);
    const fs::path target = resolve_ec ? candidate : resolved;

    const fs::path inside = target.lexically_relative(base);
    if (inside.empty() || inside == fs::path(".")) return std::nullopt;
    if (inside.begin() != inside.end() && inside.begin()->string() == "..") {
        return std::nullopt;
    }
    return target;
}

void compile_staged_payload(const Paths& paths, const fs::path& build_tree,
                            const fs::path& meta_dir, const Manifest& manifest,
                            bool approved) {
    CompileRequest request;
    request.manifest = manifest;
    request.build_tree = build_tree;
    // The build private HOME and cache live beside the staged tree and are
    // removed with it; nothing a build writes there is ever promoted.
    request.scratch_dir = build_tree.parent_path() / ".build-scratch";
    if (approved) request.approval = CompileApproval::grant();

    const CompileResult result = compile_for_host(paths, request);
    util::remove_recursive(request.scratch_dir);
    if (result.ok) {
        result.record.save(meta_dir);
        return;
    }

    ErrorRecord record = make_error_record(
        manifest.id, manifest.version, FailureStage::Compile,
        "this package could not be compiled for this machine", result.failure);
    record.launch_mode = to_string(manifest.launch_mode);
    // A portable package compiles TO the native chain; that is the whole point
    // of the type, and it is what the record should say was attempted.
    record.execution_chain = "native";
    record = ErrorStore(paths).record(std::move(record), result.stdout_text,
                                      result.stderr_text);

    std::string message = result.failure;
    if (!record.record_path.empty()) {
        message += "\n  diagnostic: " + record.record_path;
    }
    // The outcome decides the TYPE, because "you did not approve this" (exit
    // 5), "this host cannot build it" (exit 3) and "there is no sandbox to
    // build in" are different answers and must not be flattened into one.
    switch (result.outcome) {
    case CompileOutcome::NotApproved:
        throw PermissionError(message, result.hint);
    case CompileOutcome::NoSandbox:
        throw IsolationError(message, result.hint);
    case CompileOutcome::ToolchainMissing:
    case CompileOutcome::BuildFailed:
    case CompileOutcome::OutputNotAccepted:
    case CompileOutcome::Built:
        break;
    }
    throw CompileError(message, result.hint);
}

/// Health checks for a version directory (HARDENING.md §D): the manifest-
/// declared entrypoint must exist inside the version root and be a regular file,
/// and on POSIX it must be executable. Returns the list of problems found (empty
/// = healthy). Package §6 verification does NOT check that the declared
/// entrypoint is actually present in the payload — this does. It executes
/// nothing: package-controlled content is never run to verify the package.
std::vector<std::string> entrypoint_health_issues(const fs::path& version_dir,
                                                  const Manifest& manifest) {
    std::vector<std::string> issues;
    const fs::path exe = version_dir / fs::path(manifest.entrypoint_executable);
    std::error_code ec;
    if (!fs::is_regular_file(exe, ec)) {
        issues.push_back("declared entrypoint \"" +
                         manifest.entrypoint_executable +
                         "\" is missing from the payload");
        return issues; // nothing more to check
    }
#ifndef _WIN32
    const fs::perms perms = fs::status(exe, ec).permissions();
    if (!ec && (perms & fs::perms::owner_exec) == fs::perms::none) {
        issues.push_back("entrypoint \"" + manifest.entrypoint_executable +
                         "\" is not executable");
    }
#endif
    return issues;
}

/// Extract the package's flat `icons/<name>` entries into `dest` so
/// desktop::integrate_app can copy them into the hicolor theme. Entry paths
/// already passed the §2 rules in PackageReader.
void extract_icons(const PackageReader& reader, const fs::path& dest) {
    for (const PackageEntry& entry : reader.entries()) {
        const std::string& path = entry.path;
        if (path.rfind("icons/", 0) != 0) continue;
        const std::string name = path.substr(6);
        if (name.empty() || name.find('/') != std::string::npos) continue;
        util::spit(dest / name, reader.read_entry(path));
    }
}

#ifndef _WIN32
/// ZIP extraction can drop Unix mode bits — FORMAT-0.1 §1 writers (and
/// PackageWriter in particular) store entries with zeroed external
/// attributes, so the extracted entrypoint may land without its exec bit.
/// The launcher self-heals at launch time, but install time is the correct
/// place (e.g. app dirs made read-only afterwards). Owner exec is always
/// added; group/others exec mirror the corresponding read bits.
/// Definitive Architecture §7 "RUNTIME RESOLUTION" + §16: resolve the
/// application's dependency/runtime contract ONCE, at install (and repair),
/// and record the outcome. A normal native launch then only confirms the
/// recorded state still holds and execs — no compatibility-layer tax, and no
/// per-launch dependency walk.
void resolve_runtime_contract(const fs::path& version_dir,
                              const Manifest& manifest,
                              InstallationRecord& record) {
    record.runtime_resolved_at = util::now_utc_string();
    record.runtime_unresolved.clear();
    record.runtime_source.clear();
    record.runtime_glibc.clear();

    const fs::path entry = version_dir / fs::path(manifest.entrypoint_executable);
    std::error_code ec;
    if (!fs::is_regular_file(entry, ec)) return;

    // The dependency engine reads ELF. A Windows payload has no Linux runtime
    // contract to resolve — what it needs is a foreign-OS layer, which is the
    // execution resolver's question, not this one. Running the ELF analysis
    // over a PE image would produce an empty report that reads exactly like
    // "statically linked, nothing missing", which is a claim about the payload
    // that nothing checked.
    if (manifest.application_kind == ApplicationType::Windows) {
        record.runtime_source = "foreign-os";
        return;
    }

    DependencyOptions options;
    // The application's own bundled libraries are searched FIRST, then the
    // host — which is exactly the §7 "Host system / Tux32 / Bundled" ordering.
    options.payload_search_paths = {version_dir};
    options.hash_bundles = false; // hashes are already covered by the package
    DependencyReport deps;
    try {
        deps = analyze_dependencies(entry, options);
    } catch (const std::exception&) {
        // A dependency analysis that cannot run must not block an install; the
        // contract is simply recorded as unresolved-unknown (empty), and the
        // launcher does not gate on it.
        return;
    }

    // The RUNTIME contract is a second, differently-shaped question, and asking
    // it separately is the point -- see DependencyOptions::runtime_contract.
    //
    // `deps` above is the advisory analysis: it searches the payload directly,
    // which is right for "what does this package need and where would it come
    // from" and wrong for "will this start". The loader has no idea the payload
    // exists; it reaches it only through an $ORIGIN-relative rpath. A package
    // with its libraries in payload/lib and no rpath pointing there resolves
    // perfectly in the advisory view and cannot start.
    //
    // Conflating the two is what let `lexe analyze` report "0 unresolved" for a
    // package this installer refused -- two components disagreeing about the
    // same bytes, each configured reasonably, neither modelling the loader.
    DependencyOptions contract_options = options;
    contract_options.runtime_contract = true;
    DependencyReport contract;
    try {
        contract = analyze_dependencies(entry, contract_options);
    } catch (const std::exception&) {
        // Same rule as above: an analysis that cannot run must not block an
        // install, and an empty contract gates nothing.
        contract = DependencyReport{};
    }
    for (const Dependency* dependency :
         contract.of_kind(DependencyKind::Unresolved)) {
        record.runtime_unresolved.push_back(dependency->soname);
    }
    // A library that resolved ONLY through a path outside both the payload and
    // the host system directories is not satisfied, however well it resolved
    // here. That path belongs to the machine running the install — typically an
    // absolute DT_RPATH left over from a build tree — and it does not exist
    // inside the sandbox, so the loader will fail at exec.
    //
    // Recorded as unresolved because that is what it is, and because the
    // alternative is what used to happen: the contract was reported satisfied,
    // the launch was cleared, and the application exited 127 with nothing on
    // either stream. Measured with a package whose single file was its own
    // executable and whose DT_RPATH pointed into a build directory — `analyze`
    // called all three libraries "bundle", and the launch failed.
    //
    // Note the deliberate asymmetry: DependencyOrigin::System is NOT recorded
    // here. The sandbox mounts a read-only system view, so a host library in
    // /usr/lib genuinely is reachable at runtime, and refusing those would
    // break every application that correctly relies on the host.
    for (const Dependency& dependency : contract.dependencies) {
        if (dependency.origin != DependencyOrigin::Elsewhere) continue;
        if (dependency.kind == DependencyKind::Forbidden) continue;
        if (std::find(record.runtime_unresolved.begin(),
                      record.runtime_unresolved.end(), dependency.soname) ==
            record.runtime_unresolved.end()) {
            record.runtime_unresolved.push_back(dependency.soname);
        }
    }
    record.runtime_glibc = deps.max_glibc_version();

    const std::size_t bundled = deps.count(DependencyKind::Bundle);
    const std::size_t host = deps.count(DependencyKind::HostInterface);
    if (bundled != 0 && host != 0) {
        record.runtime_source = "mixed";
    } else if (bundled != 0) {
        record.runtime_source = "bundled";
    } else if (host != 0) {
        record.runtime_source = "host";
    } else {
        record.runtime_source = "static";
    }
}

void ensure_entrypoint_executable(const fs::path& version_dir,
                                  const std::string& entrypoint) {
    std::error_code ec;
    const fs::path exe = version_dir / fs::path(entrypoint);
    if (!fs::is_regular_file(exe, ec)) return;
    const fs::perms current = fs::status(exe, ec).permissions();
    if (ec) return;
    fs::perms add = fs::perms::owner_exec;
    if ((current & fs::perms::group_read) != fs::perms::none) {
        add |= fs::perms::group_exec;
    }
    if ((current & fs::perms::others_read) != fs::perms::none) {
        add |= fs::perms::others_exec;
    }
    fs::permissions(exe, add, fs::perm_options::add, ec); // best effort
}
#endif

void merge_created_files(std::vector<std::string>& into,
                         const std::vector<std::string>& add) {
    for (const std::string& file : add) {
        if (std::find(into.begin(), into.end(), file) == into.end()) {
            into.push_back(file);
        }
    }
}

} // namespace

Installer::Installer(const Paths& paths)
    : paths_(paths), locks_(make_lock_manager(paths)) {}

Installer::Installer(const Paths& paths,
                     std::shared_ptr<OperationLockManager> locks)
    : paths_(paths), locks_(std::move(locks)) {}

namespace {

// FORMAT-0.1 §9.5.1: a user's approval of an application's permissions
// "persists across update, rollback and reinstall by the same publisher key",
// and is discarded "when the application's persistent data is purged". The
// approved set lives in the installation record, which uninstall removes, so
// until this existed the approval did NOT survive an uninstall-then-reinstall
// and the runtime fell short of the normative text. Uninstall now writes it
// out, WITH the key that received it; purge removes it (appstate table).

void save_carried_approval(const Paths& paths, const InstallationRecord& rec) {
    nlohmann::json j;
    j["schema"] = 1;
    j["appId"] = rec.id;
    j["publisherKey"] = rec.publisher_key;
    j["approvedPermissions"] = rec.approved_permissions;
    const fs::path file = permission_approvals_file(paths, rec.id);
    fs::create_directories(file.parent_path());
    util::write_atomic(file, j.dump(2) + "\n");
}

/// The approval a fresh install of `m` may inherit: the saved set when -- and
/// only when -- it names this App ID and was granted under this package's key.
/// Anything else yields NOTHING, which is the safe direction for authority: an
/// unreadable, foreign, tampered, symlinked or differently-keyed record means
/// the user is asked again, never that a permission is granted unasked.
std::vector<std::string> carried_approval(const Paths& paths, const Manifest& m) {
    const fs::path file = permission_approvals_file(paths, m.id);
    std::error_code ec;
    if (!fs::is_regular_file(fs::symlink_status(file, ec))) return {};
    try {
        const nlohmann::json j = json_strict::parse(
            util::slurp_text(file), "permission approvals", limits::kMaxRecordBytes);
        if (j.at("schema").get<int>() != 1) return {};
        if (j.at("appId").get<std::string>() != m.id) return {};
        if (!crypto::same_public_key(j.at("publisherKey").get<std::string>(),
                                     m.publisher_public_key)) {
            return {}; // §9.5: a different publisher never inherits the approval
        }
        return normalized_from_ids(
                   j.at("approvedPermissions").get<std::vector<std::string>>())
            .ids;
    } catch (...) {
        return {};
    }
}

} // namespace

InstallResult Installer::install(const fs::path& lexe_file,
                                 const InstallOptions& opts) {
    // FORMAT-0.1 §6 stages 1–7 — nothing is trusted or written before this
    // passes. opts.force_arch skips only stage 7 (§6.7). Verification is
    // read-only on the package, so it runs before we take any lock.
    const Manifest manifest =
        verify_package_or_throw(lexe_file, /*check_architecture=*/!opts.force_arch);

    // Runtime-trust WS9: serialize every mutation of this App ID. A concurrent
    // install/update/rollback/remove/recovery of the SAME id waits (bounded)
    // or fails with BusyError; DIFFERENT ids take different locks and proceed
    // concurrently. Held (RAII) for the rest of this call.
    const AppLock app_lock =
        locks_->lock_app_mutation(manifest.id, "install", mutation_wait_);

    // Finish or roll back any transaction a previous run left interrupted for
    // THIS app before starting a new one (HARDENING.md §A/§C). Done UNDER the
    // mutation lock, so recovery never races another operation.
    const std::optional<std::string> healed = recover_locked(manifest.id);

    const Registry registry(paths_);
    const fs::path app_dir = registry.app_dir(manifest.id); // validates id
    (void)registry.version_dir(manifest.id, manifest.version); // validates version

    // Runtime-trust WS3/WS4: evaluate LOCAL publisher trust BEFORE anything else
    // (even before the "already installed" check) so a locally blocked App ID is
    // refused unconditionally. Authenticity (§6) already passed, so the signature
    // is valid; this gate decides key CONTINUITY. A first-seen key is allowed
    // (the separate --yes/confirm is the install consent); a known matching key
    // is allowed; a changed key, a locally blocked App ID, a corrupt trust
    // record, or data retained under a different key are all rejected with typed
    // errors. No --yes / --force / --accept-permissions bypasses this.
    {
        std::optional<std::string> retained_owner;
        const fs::path owner = registry.data_owner_marker(manifest.id);
        std::error_code ec;
        if (fs::is_regular_file(owner, ec)) {
            std::string prior = util::slurp_text(owner);
            while (!prior.empty() &&
                   (prior.back() == '\n' || prior.back() == '\r' ||
                    prior.back() == ' ')) {
                prior.pop_back();
            }
            if (!prior.empty()) retained_owner = prior;
        }
        const TrustEvaluation eval = TrustStore(paths_).evaluate(
            manifest.id, manifest.decoded_public_key(), SignatureState::Valid,
            retained_owner);
        eval.throw_if_rejected();
    }

    InstallationRecord record;
    std::string previous_version; // active version before this install ("" = fresh)
    if (registry.is_installed(manifest.id)) {
        record = registry.read_record(manifest.id);
        // Defense in depth: the installation record pins the publisher key
        // (FORMAT-0.1 §7.1). A different key MUST NOT silently take over an
        // installed id — this catches even the case where the local trust
        // record was forgotten while the app stayed installed. Reported as a
        // ChangedKey trust rejection (runtime-trust WS4).
        // Compared as KEY MATERIAL, not as text. The recorded string and the
        // manifest string are both canonical today -- decode_public_key
        // enforces that -- but this is the check that decides whether a
        // different publisher may take over an installed id, and it should not
        // depend on an encoding rule enforced in another file. Base64 leaves
        // the unused bits of its final group free, so "the same key" and "the
        // same string" are not the same question.
        if (!crypto::same_public_key(record.publisher_key,
                                     manifest.publisher_public_key)) {
            throw ChangedKeyError(
                "refusing: " + manifest.id +
                " is installed under key " + record.publisher_key +
                " but this package is signed with " +
                manifest.publisher_public_key +
                ". FORMAT 0.1 has no authenticated key rotation — `lexe purge " +
                manifest.id + "` forgets the application, its data and its "
                "trust record, after which a new publisher key installs as a "
                "first install.");
        }
        try {
            previous_version = registry.current_version(manifest.id);
        } catch (const NotFoundError&) {
            // No usable current pointer — allow the install to self-heal.
        }
        if (previous_version == manifest.version) {
            // ... unless THIS call is what made it current.
            //
            // `install` opens by running recovery, so an install interrupted at
            // or after promotion is completed forward before the new request is
            // considered. When that happens, the application arrives here
            // already at the requested version -- and reporting a conflict
            // would be exactly backwards. An evidence audit hit this from the
            // other side: after a SIGKILLed first install, `lexe list` showed
            // nothing installed, and `lexe install <same package>` then exited
            // 6 saying it was "already installed and current". The end state
            // was right and the healing was good; the account of it was wrong.
            //
            // It matters beyond wording because exit 6 is load-bearing
            // (docs/ERRORS.md §6): it means the requested state ALREADY held
            // and this call did nothing. A provisioning script that treats 6 as
            // "no action taken, nothing to log" was being told the opposite of
            // the truth on the one occasion worth logging.
            //
            // Success is the honest answer, and it is a complete one:
            // `recover_locked` finishes the whole transaction -- manifest,
            // hashes, entrypoint mode, desktop integration, installation
            // record, atomic activation and trust persistence -- so there is
            // nothing an ordinary install would additionally have done.
            if (healed.has_value() && *healed == manifest.version) {
                return InstallResult{manifest.id, manifest.version, app_dir};
            }

            // BusyError -> exit 6, "busy, or an OPERATION CONFLICT". Not the
            // untyped catch-all, which is exit 1 and means "failed for a reason
            // with no more specific code".
            //
            // This was exit 1, and exit 1 is also what a genuinely broken
            // install returns, so no script could tell "somebody already did
            // this" from "something went wrong". An independent pass hit it in
            // 22 of 32 concurrent `install||install` races and in every
            // idempotent re-run -- the ordinary shape of a provisioning script
            // that installs whatever is missing. docs/ERRORS.md section 1
            // already had the right code; nothing was using it.
            //
            // The remedy in the message is unchanged and still accurate: the
            // files can be reinstalled, that is simply a different operation.
            throw BusyError(manifest.id + " " + manifest.version +
                            " is already installed and current; use `lexe repair " +
                            manifest.id + "` to reinstall its files",
                            "Nothing was changed because nothing needed to be. "
                            "Exit 6 here means the requested state already holds "
                            "-- distinct from exit 1, which would mean the "
                            "install was attempted and failed.");
        }
        // A direct install that moves BACKWARDS must be asked for (§7.1).
        //
        // `lexe update` refuses a lower version (§7 check 7); a direct install
        // did not, because the package is authentic and nothing in verification
        // objects to it. So `lexe install app-1.0.0.lexe` over 3.0.0 succeeded
        // silently -- and an old, still-validly-signed package is precisely
        // what an attacker who cannot forge a signature still possesses.
        //
        // Refused rather than warned, because a warning on a path that ends in
        // success is a warning nobody reads. Downgrading remains available: it
        // is legitimate when a new version is broken.
        if (!opts.allow_downgrade && !previous_version.empty() &&
            version_less(manifest.version, previous_version)) {
            throw Error(
                "refusing to move " + manifest.id + " backwards from " +
                    previous_version + " to " + manifest.version,
                "Installing an older version is possible, but it has to be "
                "asked for: re-run with `--allow-downgrade`. An older release "
                "may be missing fixes present in " + previous_version + ".");
        }
    }

    // Runtime-trust WS2: parse + normalize + validate the requested permissions
    // (reject unknown / duplicate / conflicting) BEFORE anything is installed,
    // and record the approved set + digest as the consent anchor.
    const NormalizedPermissions requested_perms =
        normalize_permissions(manifest.permissions);

    // Runtime-trust WS5: on an UPGRADE, an update that expands the approved
    // permission set requires explicit consent — a bare confirmation never
    // grants new authority. Removals and reordering are not an expansion.
    if (registry.is_installed(manifest.id) && !previous_version.empty()) {
        const NormalizedPermissions approved =
            normalized_from_ids(record.approved_permissions);
        const PermissionDelta delta =
            permission_delta(approved, requested_perms);
        if (delta.expands() && !opts.allow_permission_expansion) {
            std::string added;
            for (const std::string& id : delta.added) {
                if (!added.empty()) added += ", ";
                added += id;
            }
            // The message states the problem; the fix rides along as the hint,
            // so the CLI does not print the same instruction twice.
            throw PermissionError(
                manifest.name + " " + manifest.version +
                    " requests permissions you have not approved for it: " +
                    added,
                "Review what those permissions allow, then re-run with "
                "--accept-permissions to grant them.");
        }
    }

    const PackageReader reader(lexe_file);
    const std::vector<std::uint8_t> manifest_bytes =
        reader.read_entry("lexe.json");
    const std::vector<std::uint8_t> hashes_bytes =
        reader.read_entry("metadata/hashes.json");

    // The installation record we intend to commit (created_files are added
    // after desktop integration). It is stored in the transaction journal so a
    // crash-recovered promotion can write a faithful record (HARDENING.md §A).
    InstallationRecord new_record = record; // carries prior update_url/createdFiles
    new_record.id = manifest.id;
    new_record.version = manifest.version;
    new_record.source = opts.source.value_or(lexe_file.string());
    new_record.publisher_key = manifest.publisher_public_key; // trust anchor §7.1
    new_record.channel = opts.channel;
    if (new_record.update_url.empty() && manifest.updates_enabled) {
        // First install: the manifest's update source becomes the default. A
        // source the user already configured is never silently replaced
        // (SPEC "Update Ownership").
        new_record.update_url = manifest.updates_manifest_url;
    }
    new_record.installed_at = util::now_utc_string();
    new_record.approved_permissions = requested_perms.ids;
    new_record.permissions_digest = requested_perms.digest;
    // A FRESH install (nothing installed) of an App ID this machine uninstalled
    // earlier inherits the approval saved then -- only for the same publisher
    // key (carried_approval). Union, not replacement: the approval covers a set,
    // and reinstalling a version that requests less must not narrow what was
    // granted, exactly as a rollback must not (§9.5.1).
    if (!registry.is_installed(manifest.id)) {
        const std::vector<std::string> carried = carried_approval(paths_, manifest);
        if (!carried.empty()) {
            std::vector<std::string> both = carried;
            both.insert(both.end(), requested_perms.ids.begin(),
                        requested_perms.ids.end());
            std::sort(both.begin(), both.end());
            both.erase(std::unique(both.begin(), both.end()), both.end());
            const NormalizedPermissions merged = normalized_from_ids(both);
            new_record.approved_permissions = merged.ids;
            new_record.permissions_digest = merged.digest;
        }
    }

    // Transactional staged install (HARDENING.md §A). Nothing becomes active
    // until the staged tree is validated and atomically promoted; a failure
    // before promotion leaves the previous version untouched.
    InstallTransaction txn(paths_, manifest.id, manifest.version);
    try {
        fault::maybe("before-staging");
        txn.begin(previous_version, new_record.to_json());

        // (3) Extract payload and (4) write meta INTO staging — never the live
        // version directory.
        fault::maybe("during-extraction"); // staging exists, extraction not done
        reader.extract_payload(txn.staging_version_dir());
        fault::maybe("after-extraction");
#ifndef _WIN32
        ensure_entrypoint_executable(txn.staging_version_dir(),
                                     manifest.entrypoint_executable);
#endif
        util::spit(txn.staging_meta_dir() / "lexe.json", manifest_bytes);
        util::spit(txn.staging_meta_dir() / "hashes.json", hashes_bytes);
        // Where THIS version came from, beside this version's hashes.
        //
        // installation.json has a single `source` field, and it necessarily
        // means "where the most recent install came from". Repair needs
        // something else: where the CURRENT version came from. After an update
        // and a rollback those are different packages, and repair was rejecting
        // the only package it knew about because its version did not match the
        // one being repaired -- so a rolled-back application could not be
        // repaired at all, reporting "corrupt or missing file(s) that could not
        // be repaired" while the right package sat on disk.
        util::spit(txn.staging_meta_dir() / "source.txt",
                   opts.source.value_or(lexe_file.string()));

        // (4b) HOST-ISA COMPILE (Definitive Architecture §5/§7). A portable
        // package's payload is source; the program does not exist yet. It is
        // built HERE — inside the staged tree, before promotion — so a build
        // that fails, produces nothing, or produces the wrong thing leaves the
        // previously installed version exactly where it was.
        //
        // The result is recorded in the per-version meta store next to
        // hashes.json, because the compiled entrypoint is not covered by the
        // package's signed hashes: it did not exist when the package was
        // signed. Recording it here is what makes tamper detection and repair
        // work identically for a compiled entrypoint and an extracted one.
        if (manifest.application_kind == ApplicationType::Portable) {
            compile_staged_payload(paths_, txn.staging_version_dir(),
                                   txn.staging_meta_dir(), manifest,
                                   opts.approve_compile);
        }
        // Definitive Architecture §15.1 "Durable integration": per-application
        // desktop artifacts must be regenerable FROM INSTALLED STATE, with no
        // package file present. Icons are one of those artifacts, so they are
        // RETAINED in the per-version meta store and promoted atomically with
        // the version — not extracted to a scratch directory and thrown away.
        // Without this, `lexe doctor --repair` has no icon source and could
        // only ever drop icon registrations.
        extract_icons(reader, txn.staging_meta_dir() / "icons");
        txn.mark_staged();
        fault::maybe("after-staged");

        // (5) Staged validation: the extracted tree must match its own signed
        // hashes, and pass the health check (declared entrypoint present +
        // executable), BEFORE anything is promoted. Because this gate runs
        // before the `current` flip, an upgrade to a package that fails its
        // health check NEVER replaces the working version — the previous
        // known-good version simply stays active (HARDENING.md §D auto-rollback,
        // achieved by never activating an unhealthy version).
        validate_staged_tree(txn.staging_version_dir(),
                             txn.staging_meta_dir() / "hashes.json");
        {
            const std::vector<std::string> issues =
                entrypoint_health_issues(txn.staging_version_dir(), manifest);
            if (!issues.empty()) {
                throw VerificationError("post-install health check failed: " +
                                        issues.front());
            }
        }
        txn.mark_verified();

        // (6) Atomic promotion of versions/<v> + meta/<v>.
        fault::maybe("before-promote");
        txn.promote();
        fault::maybe("after-promote"); // version in place, not yet active

        // (7) Activation — idempotently redone by recovery if interrupted:
        // active copies, desktop integration, record, then the atomic `current`
        // flip last.
        registry.write_manifest_bytes(manifest.id, manifest_bytes);
        util::spit(app_dir / "hashes.json", hashes_bytes);

        std::vector<std::string> created_files = record.created_files;
        if (opts.desktop_integration) {
            // Definitive Architecture §14.1/§15.1: integration is INSTALLED
            // SYSTEM STATE, recorded and repairable — and it produces the
            // first-class run.lexe launch artifact, so the raw payload never
            // becomes the user-facing launch object. The icon source is the
            // RETAINED per-version copy, which is the same source `lexe doctor
            // --repair` uses later.
            DesktopIntegration integration(paths_);
            (void)integration.install_runtime_handler();
            const IntegrationReport app_integration = integration.install_app(
                manifest,
                registry.meta_dir(manifest.id, manifest.version) / "icons");
            std::vector<std::string> integration_files;
            for (const ArtifactCheck& check : app_integration.checks) {
                integration_files.push_back(check.artifact.path);
            }
            merge_created_files(created_files, integration_files);
        }
        new_record.created_files = std::move(created_files);
        // §16: resolve the runtime contract once, here, and record it.
        resolve_runtime_contract(registry.version_dir(manifest.id, manifest.version),
                                 manifest, new_record);
        registry.write_record(new_record);

        registry.set_current_version(manifest.id, manifest.version); // atomic
        txn.mark_record_updated();
        fault::maybe("after-record"); // activated, cleanup not yet done

        // (8) Done: drop staging and clear the journal.
        txn.commit();
    } catch (const fault::Injected&) {
        // Simulate a crash: leave the journal mid-transaction so recovery runs
        // on the NEXT invocation (recover_all), not here. Do not clean up.
        throw;
    } catch (...) {
        // A genuine error: drive the app back to a consistent state per the
        // journal, then propagate. Pre-promotion → rolled back (previous
        // untouched); post-promotion → completed forward (new version active).
        try {
            recover(manifest.id);
        } catch (...) {
        }
        throw;
    }

    // Runtime-trust WS8: record the data owner. Persistent data belongs to the
    // App ID, and this marker pins the publisher key that owns it so a later
    // reinstall under a DIFFERENT key cannot inherit retained data. Written
    // only after a fully committed install; a pre-existing marker (same key)
    // is left as-is. Never touched: the installer does not read or execute the
    // app's own data — this is a sibling metadata file it owns.
    {
        std::error_code ec;
        fs::create_directories(registry.app_data_dir(manifest.id), ec);
        util::spit(registry.data_owner_marker(manifest.id),
                   std::string_view(manifest.publisher_public_key));
    }

    // Runtime-trust WS4: persist the local trust binding — ONLY here, after a
    // fully committed install (a failed install never records trust). Idempotent:
    // it refreshes an existing same-key record and creates one on first install.
    // The trust gate above already rejected a changed/blocked key, so this cannot
    // rebind. explicit_trust records the user deliberately trusting the key (a
    // stronger, separate act than consenting to the install).
    {
        TrustStore trust(paths_);
        trust.record_accept(
            manifest.id, manifest.decoded_public_key(), opts.explicit_trust,
            opts.explicit_trust ? "install-trust" : "install-accept");
    }

    // A saved approval has now been merged into the committed record -- or was
    // refused because it belonged to another key. Either way it is spent:
    // left behind, a differently-keyed approval could never be honoured, and a
    // same-keyed one would be a second copy of what the record now holds.
    {
        std::error_code ec;
        fs::remove(permission_approvals_file(paths_, manifest.id), ec);
    }

    return InstallResult{manifest.id, manifest.version, app_dir};
}

void Installer::recover(const std::string& id) {
    // Recovery mutates the app, so it takes the per-app mutation lock — this is
    // what makes recovery serialize with a same-App install/update/rollback
    // (runtime-trust WS9).
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "recover", mutation_wait_);
    recover_locked(id);
}

fs::path Installer::removal_tomb(const std::string& id) const {
    // app_dir validates the id, so the tombstone name is as safe as it is.
    return Registry(paths_).app_dir(id).parent_path() / ".removing" / id;
}

void Installer::sweep_removed_locked(const std::string& id) {
    // The remains of an uninstall that was killed after it detached the
    // application. Unreachable already, so this is tidiness, not correctness --
    // which is why a failure here is not allowed to fail the operation that
    // happened to notice it.
    std::error_code ec;
    fs::remove_all(removal_tomb(id), ec);
}

std::optional<std::string> Installer::recover_locked(const std::string& id) {
    // An interrupted PURGE is finished first, and in full, before this App ID is
    // considered for anything else. The user asked .LEXE to forget it; an
    // install that went ahead with the old trust record, data owner or
    // preferences half in place would install a RETURNING application while
    // the user was told -- by the act of purging -- that it would be a first
    // one. If the purge cannot finish (a version is running, a file will not
    // delete) this throws, and so does the install: fail closed.
    if (purge_pending(paths_, id)) {
        purge_locked(id);
        return std::nullopt;
    }
    // An interrupted UNINSTALL is finished here too: it is the other
    // transaction that can be cut short, and this is where interrupted work is
    // completed before a new operation on the same id begins.
    sweep_removed_locked(id);
    const Registry registry(paths_);
    TransactionJournal journal;
    try {
        journal = read_journal(paths_, id);
    } catch (const Error&) {
        // An unreadable/corrupt journal: leave the app as-is rather than guess.
        return std::nullopt;
    }
    if (journal.phase == TxnPhase::None) return std::nullopt;

    InstallTransaction txn(paths_, id, journal.target_version);

    // Pre-promotion → roll back. The previous version and `current` were never
    // touched, so removing staging (and any orphan target dirs) restores the
    // app to "previous active" or "safely absent".
    if (journal.phase == TxnPhase::Preparing ||
        journal.phase == TxnPhase::Staged ||
        journal.phase == TxnPhase::Verified) {
        txn.abort();
        return std::nullopt;
    }

    // Promoted / RecordUpdated → complete forward. The version + meta are in
    // place and were validated before promotion; make them active idempotently.
    const fs::path app_dir = registry.app_dir(id);
    const fs::path meta = registry.meta_dir(id, journal.target_version);
    std::error_code ec;
    if (!fs::is_regular_file(meta / "lexe.json", ec) ||
        !fs::is_regular_file(meta / "hashes.json", ec)) {
        // Promotion metadata is gone — cannot complete; fall back to rollback.
        txn.abort();
        return std::nullopt;
    }
    const std::vector<std::uint8_t> manifest_bytes =
        util::slurp(meta / "lexe.json");
    const std::vector<std::uint8_t> hashes_bytes =
        util::slurp(meta / "hashes.json");
    const Manifest manifest = Manifest::parse(manifest_bytes);

    registry.write_manifest_bytes(id, manifest_bytes);
    util::spit(app_dir / "hashes.json", hashes_bytes);
#ifndef _WIN32
    ensure_entrypoint_executable(registry.version_dir(id, journal.target_version),
                                 manifest.entrypoint_executable);
#endif

    // Rebuild the record from the journal's pending record (falling back to a
    // minimal record from the manifest), then refresh the desktop entry + MIME
    // best-effort (no icons on the recovery path — the package may be gone).
    InstallationRecord rec;
    try {
        rec = InstallationRecord::from_json(journal.pending_record);
    } catch (const Error&) {
        rec.id = id;
        rec.publisher_key = manifest.publisher_public_key;
        rec.installed_at = util::now_utc_string();
    }
    rec.id = id;
    rec.version = journal.target_version;
    std::vector<std::string> created = rec.created_files;
    try {
        DesktopIntegration integration(paths_);
        const IntegrationReport app_integration = integration.install_app(
            manifest, registry.meta_dir(id, journal.target_version) / "icons");
        std::vector<std::string> integration_files;
        for (const ArtifactCheck& check : app_integration.checks) {
            integration_files.push_back(check.artifact.path);
        }
        merge_created_files(created, integration_files);
    } catch (...) {
        // Desktop integration is best-effort; a recovered install still works
        // from the CLI and a later `lexe repair` restores full integration.
    }
    rec.created_files = std::move(created);
    registry.write_record(rec);

    registry.set_current_version(id, journal.target_version); // atomic activation

    // Runtime-trust WS4: a PROMOTED install committed, so recovery completes its
    // trust persistence too (never for a rolled-back transaction — that path
    // returns above without reaching here). Idempotent, derives the key from the
    // committed manifest, and NEVER records explicit trust. Best-effort: the
    // install is already active and the installation record pins the key, so a
    // trust-record edge (e.g. a block set during the crash window) must not
    // fail the recovery.
    try {
        TrustStore(paths_).record_accept(id, manifest.decoded_public_key(),
                                         false, "install-accept");
    } catch (const TrustError&) {
    }

    txn.commit();
    // Completed FORWARD. The caller -- `install` in particular -- needs this to
    // describe what happened: the application became installed and current
    // because of THIS call, not before it.
    return journal.target_version;
}

void Installer::recover_all() {
    // Serialize recovery passes with one another (runtime-trust WS9). Per-app
    // recovery still takes each app's own mutation lock underneath this, so a
    // busy app is skipped rather than blocked (unrelated apps are not
    // serialized by this global lock — they only wait to be enumerated).
    const GlobalRecoveryLock recovery_lock =
        locks_->lock_global_recovery(mutation_wait_);

    std::error_code ec;
    const fs::path apps = paths_.apps_dir();
    if (!fs::is_directory(apps, ec)) return;
    // A crashed FRESH install has a txn.json but no installation.json, so we
    // cannot use list_installed(); scan every app dir for a journal.
    std::vector<std::string> ids;
    for (const auto& entry : fs::directory_iterator(apps, ec)) {
        std::error_code e2;
        if (!entry.is_directory(e2)) continue;
        if (fs::is_regular_file(entry.path() / "txn.json", e2)) {
            ids.push_back(entry.path().filename().string());
        }
    }
    // Unfinished purges: `.removing/<id>.purge`. An application that is not
    // installed any more has no txn.json to be found by, and that is the
    // ordinary shape of a purge interrupted after it detached the program.
    for (const auto& entry : fs::directory_iterator(apps / ".removing", ec)) {
        const fs::path name = entry.path().filename();
        if (name.extension() != ".purge") continue;
        const std::string id = name.stem().string();
        if (app_id_is_valid(id)) ids.push_back(id);
    }
    for (const std::string& id : ids) {
        try {
            recover(id);
        } catch (...) {
            // One app's recovery failure must not block the others.
        }
    }
}

HealthReport Installer::check_health(const std::string& id) const {
    const Registry registry(paths_);
    const std::string current = registry.current_version(id); // NotFoundError
    const fs::path app_dir = registry.app_dir(id);
    const fs::path version_dir = registry.version_dir(id, current);
    const Manifest manifest = registry.read_manifest(id); // NotFoundError

    HealthReport report;
    // Identity: the active manifest must describe THIS application.
    if (manifest.id != id) {
        report.issues.push_back("manifest id \"" + manifest.id +
                                "\" does not match installed id \"" + id + "\"");
    }
    // Entrypoint present + executable.
    for (std::string& issue : entrypoint_health_issues(version_dir, manifest)) {
        report.issues.push_back(std::move(issue));
    }
    // Integrity: every recorded payload file present and matching its hash.
    std::error_code ec;
    fs::path hashes_file = meta_dir(app_dir, current) / "hashes.json";
    if (!fs::is_regular_file(hashes_file, ec)) {
        hashes_file = app_dir / "hashes.json";
    }
    if (fs::is_regular_file(hashes_file, ec)) {
        const std::vector<PayloadHash> expected =
            load_payload_hashes(hashes_file);
        for (const PayloadHash& bad :
             corrupt_payload_files(version_dir, expected)) {
            report.issues.push_back("payload file missing or corrupt: " +
                                    bad.key);
        }
    } else {
        report.issues.push_back("no recorded hashes to verify against");
    }
    report.ok = report.issues.empty();
    return report;
}

std::vector<LaunchLease> Installer::hold_versions_or_refuse(const std::string& id) {
    // Runtime-trust WS9: never delete the binaries of an app that is currently
    // running. A launch holds a SHARED lease on its version; probe every
    // installed version with a non-blocking EXCLUSIVE gc-lock. If any is leased,
    // a live process is using it — refuse with BusyError (the documented
    // policy) rather than silently pull files out from under it. Holding the
    // exclusive locks across the removal also prevents a launch from STARTING
    // mid-removal (its shared lease would block on our exclusive hold).
    //
    // Taken ONCE, by the caller, before anything is written. flock conflicts
    // between two descriptors of the same process, so a second probe inside the
    // removal would refuse against our own hold.
    const Registry registry(paths_);
    std::vector<LaunchLease> held;
    for (const std::string& v : registry.installed_versions(id)) {
        std::optional<LaunchLease> vlock = locks_->try_lock_version_for_gc(id, v);
        if (!vlock.has_value()) {
            throw BusyError("cannot remove " + id +
                            ": it is currently running (version " + v +
                            " is in use); close it and try again");
        }
        held.push_back(std::move(*vlock));
    }
    return held;
}

void Installer::uninstall(const std::string& id) {
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "uninstall", mutation_wait_);
    // Not finished here, deliberately. A purge deletes the application's data
    // and its trust record; uninstall promises never to, and finishing someone
    // else's purge would break that promise on the one occasion it mattered.
    if (purge_pending(paths_, id)) throw purge_unfinished_error(id);
    const Registry registry(paths_);
    const InstallationRecord record = registry.read_record(id); // NotFoundError
    const std::vector<LaunchLease> held = hold_versions_or_refuse(id);
    // Before anything is removed: if the removal is interrupted, the approval
    // is already safe, and while the app is still installed this file is
    // never read.
    save_carried_approval(paths_, record);
    remove_installation_locked(id);
}

void Installer::remove_installation_locked(const std::string& id) {
    const Registry registry(paths_);
    // The record names files outside apps/<id> that this installation created.
    // A purge may meet an application whose record is gone or unreadable (that
    // is what interrupted removals leave); its integration artifacts are still
    // recorded in integration.json, which remove_app() reads, so nothing is
    // lost by going on without it.
    std::optional<InstallationRecord> record;
    if (registry.is_installed(id)) {
        try {
            record = registry.read_record(id);
        } catch (const NotFoundError&) {
            throw;
        } catch (const Error&) {
            if (!purge_pending(paths_, id)) throw; // uninstall: report it
        }
    }

    // Versions whose lease files are this application's: the ones in its own
    // directories -- the live one and the remains of an interrupted uninstall.
    // Never by matching names in locks/ (appstate.hpp says why). Collected
    // first: once the directory is detached, installed_versions() answers
    // nothing.
    std::vector<std::string> lease_versions = registry.installed_versions(id);
    {
        std::error_code ec;
        const fs::path tomb_versions = removal_tomb(id) / "versions";
        if (fs::is_directory(tomb_versions, ec)) {
            for (const auto& e : fs::directory_iterator(tomb_versions, ec)) {
                const std::string v = e.path().filename().string();
                if (version_string_is_valid(v)) lease_versions.push_back(v);
            }
        }
    }

    // Desktop-side removal first: this also forgets the app in the durable
    // integration state, so `lexe doctor` does not later try to "repair" an
    // application that is deliberately gone (§15.1).
    DesktopIntegration(paths_).remove_app(id);
    // … then a portable sweep so every recorded file is gone even where the
    // desktop module is a recorded no-op (FORMAT-0.1 §9: uninstall removes
    // everything recorded in installation.json, then the app directory).
    // Every one of these paths is asked `may_delete` first, because
    // `installation.json` is local unsigned state and a recorded path is not a
    // licence to remove a file.
    //
    // Without the guard this loop deleted whatever the record named.
    // Demonstrated: two paths appended to `createdFiles` -- an ordinary
    // directory and an ordinary file, both far outside LEXE_HOME -- and
    // `lexe remove` (now `uninstall`) destroyed both, the directory
    // RECURSIVELY, while reporting
    // a clean removal.
    //
    // The same defect was found and fixed once already, in
    // `integration.cpp`: artifact records pointing into $HOME, deleted by
    // `doctor --repair`. `may_delete` is the fix from that round. It was
    // applied to the module where the bug was demonstrated and not to this
    // one, which reads a different file for the same purpose -- so the rule
    // held on one path and not on its sibling, and HARDENING.md went on
    // claiming "installer-owned cleanup cannot delete arbitrary paths" for
    // both. A guard only one caller honours is a convention, not an invariant.
    //
    // It is not a privilege boundary: whoever can write this record can
    // usually delete these files directly. The likelier route is not malice at
    // all -- a truncated or garbled record with a mangled path reaches the same
    // `remove_recursive`, and this one is recursive.
    //
    // Refusals are reported rather than swallowed: a record naming a path
    // outside the tree is itself a finding.
    refused_paths_.clear();
    for (const std::string& file :
         record.has_value() ? record->created_files : std::vector<std::string>{}) {
        const fs::path path(file);
        if (!may_delete(paths_, path)) {
            refused_paths_.push_back(file);
            continue;
        }
        util::remove_recursive(path);
    }

    // The application directory goes in ONE step: renamed out of `apps/`, and
    // only then deleted.
    //
    // It used to be one `remove_recursive(app_dir)`, and that directory holds
    // both the CLAIM (`installation.json`) and what the claim refers to
    // (`versions/`). `remove_all` deletes them in whatever order readdir
    // returns, so an uninstall killed partway could leave installation.json
    // recording 3.0.0 as current with versions/3.0.0 already gone -- an
    // application `lexe list` reports as installed, whose files are missing.
    // FORMAT-0.1 §9.2 forbids exactly that state "at any instant at which a
    // runtime could be terminated", and HARDENING.md §C.9 names the case. The
    // lifecycle lane (02_interrupted, "killed during uninstall") hit it in 6
    // of 12 runs, idle or loaded alike: which entry readdir yields first.
    //
    // A rename within `apps/` is atomic, so at every instant the application
    // is either wholly present or wholly absent. The tombstone sits one level
    // down, in `apps/.removing/`, where nothing that enumerates applications
    // looks: `list_installed` wants `apps/<x>/installation.json` and
    // `recover_all` wants `apps/<x>/txn.json`, and `.removing` holds neither.
    // A kill after the rename leaves only unreachable bytes, swept by the next
    // mutation of this id (`sweep_removed_locked`, under the same lock).
    sweep_removed_locked(id);
    const fs::path tomb = removal_tomb(id);
    std::error_code detach_ec;
    if (fs::exists(fs::symlink_status(registry.app_dir(id), detach_ec))) {
        fs::create_directories(tomb.parent_path());
        fs::rename(registry.app_dir(id), tomb);
    }
    fault::maybe("uninstall-after-detach");
    util::remove_recursive(tomb);

    // The per-version LEASE files, which used to outlive the application.
    //
    // `locks/` accumulated one `<id>.v.<version>.lease` for every version of every
    // application ever installed, and nothing deleted them -- not even
    // `remove --purge-data` (now `purge`), whose entire promise is that nothing is
    // left. That is the unbounded part: versions accumulate without limit, while
    // applications are bounded by the applications someone installs.
    //
    // Safe HERE specifically because of what has already happened above: this
    // process holds an exclusive lock on every one of these versions (the in-use
    // check), and the application directory is gone. A launch that was blocked on
    // one of these leases will acquire it against a fresh inode, find no version
    // to run, and fail honestly -- there is nothing left for the lease to protect.
    //
    // The per-app MUTATION lock is deliberately NOT deleted, and that asymmetry is
    // the whole point of this comment.
    //
    // `flock` is per-inode, not per-path. Unlinking a lock file therefore does not
    // release it -- it makes the NEXT opener create a different inode and acquire a
    // lock that excludes nobody. For the mutation lock that is mutual exclusion
    // silently breaking: this uninstall holds inode A while a concurrent install
    // creates inode B, locks it successfully, and starts extracting into the
    // directory tree this function is in the middle of deleting.
    //
    // So it stays. One file per application is bounded state, and correctness costs
    // more than tidiness is worth. A first draft of this deleted it and reasoned
    // that "the worst case is a lock file that reappears"; the worst case is two
    // writers.
    std::error_code lock_ec;
    for (const std::string& version : lease_versions) {
        fs::remove(registry.version_lease_file(id, version), lock_ec);
    }

    // Everything else the table marks as installation material or debris:
    // cache, downloaded updates, launch-reference scratch. The cache used to
    // survive a plain removal (the old `remove` default) for no stated reason
    // -- debris that outlived the installation because nobody deleted it, which
    // is exactly what an uninstall must not leave. Persistent data, the trust
    // record, compatibility preferences and error history are NOT touched
    // here: they are SurvivesUninstall, and only purge removes them.
    for (const AppStateEntry& entry : app_state_table(paths_, id)) {
        if (entry.fate != StateFate::RemovedByUninstall) continue;
        util::remove_recursive(entry.path); // throws on failure; missing is fine
    }
}

Installer::PurgeReport Installer::purge(const std::string& id) {
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "purge", mutation_wait_);
    return purge_locked(id);
}

Installer::PurgeReport Installer::purge_locked(const std::string& id) {
    PurgeReport report;
    report.finished_interrupted = purge_pending(paths_, id);
    const std::vector<AppStateEntry> table = app_state_table(paths_, id);

    // What exists BEFORE: both the report and the "nothing to purge" answer
    // come from it. The mutation lock (Kept) is not state, and an empty integration
    // scope is not either.
    std::vector<AppStateEntry> before;
    for (const AppStateEntry& e : present_entries(table)) {
        if (e.fate != StateFate::Kept) before.push_back(e);
    }
    const bool had_integration =
        !IntegrationState::load(paths_).scope(id).empty();
    const Registry registry(paths_);
    report.was_installed = registry.is_installed(id);

    if (!report.finished_interrupted && before.empty() && !had_integration) {
        // After a purge, .LEXE genuinely does not know this App ID -- so the
        // answer is the one a never-installed App ID gets, and it is the right
        // one: forgetting it was the point. Not 6 ("removed earlier"): nothing
        // here can show that it ever was.
        throw NotFoundError(
            "nothing to purge: .LEXE holds no state for " + id,
            "Either it was never installed here, or it has already been "
            "purged.");
    }

    // Refuse a running application BEFORE the journal is written, so a refusal
    // leaves nothing behind -- not even an unfinished purge that would then
    // block the launch the user is in the middle of.
    const std::vector<LaunchLease> held = hold_versions_or_refuse(id);

    // The journal. From here the purge only rolls FORWARD: an interruption at
    // any later point is finished by the next `lexe purge` or `lexe install` of
    // this App ID, and launch, uninstall and the trust commands refuse until
    // then. Written atomically (temp + rename), so it is either there or not.
    const fs::path journal = purge_journal(paths_, id);
    fs::create_directories(journal.parent_path());
    if (!report.finished_interrupted) {
        util::write_atomic(journal, std::string("{\"id\":\"") + id +
                                        "\",\"startedAt\":\"" +
                                        util::now_utc_string() + "\"}\n");
    }
    fault::maybe("purge-after-journal");

    remove_installation_locked(id);
    fault::maybe("purge-after-detach");

    // Test seam (LEXE_TEST_FAULT only): the bytes of a VALID trust record, to be
    // written back below as a writer outside this lock might. A valid record,
    // not a corrupt one, because a valid record is the one that would be
    // honoured -- "purged, and still trusted" is the failure being simulated.
    std::optional<std::string> resurrect;
    if (fault::active("purge-resurrect-trust") &&
        fs::is_regular_file(registry.trust_record_file(id))) {
        resurrect = util::slurp_text(registry.trust_record_file(id));
    }

    // The deliberately persistent state uninstall keeps, in TABLE order -- which
    // puts the trust record first (appstate.cpp): it is the one that decides
    // whether a later install of this App ID is a first install.
    for (const AppStateEntry& entry : table) {
        if (entry.fate != StateFate::SurvivesUninstall) continue;
        util::remove_recursive(entry.path);
        if (entry.path == registry.trust_record_file(id)) {
            fault::maybe("purge-after-trust");
        }
    }
    fault::maybe("purge-before-commit");
    if (resurrect.has_value()) {
        util::write_atomic(registry.trust_record_file(id), *resurrect);
    }

    // The post-check, and the reason the journal outlives the deletions above.
    // remove_recursive throws on the failures it can see; this catches the ones
    // it cannot -- something recreated, a removal that returned success over a
    // path that is still there -- and refuses to call the purge done. A purge
    // that leaves the trust record behind and says "purged" is the failure this
    // operation must never have.
    std::vector<std::string> remaining;
    for (const AppStateEntry& e : present_entries(table)) {
        if (e.fate != StateFate::Kept) remaining.push_back(e.what);
    }
    if (!IntegrationState::load(paths_).scope(id).empty()) {
        remaining.push_back("desktop integration records");
    }
    if (!remaining.empty()) {
        std::string list;
        for (const std::string& r : remaining) list += "\n  - " + r;
        throw Error("purge of " + id + " did not complete; still present:" + list,
                    "Nothing was reported as purged. Fix the cause (file "
                    "permissions, a read-only mount) and run `lexe purge " +
                        id + "` again. Until it finishes, " + id +
                        " cannot be launched, and installing it finishes the "
                        "purge first.");
    }

    fs::remove(journal); // throws on failure: the purge is not done until this
    for (const AppStateEntry& e : before) report.removed.push_back(e.what);
    if (had_integration) report.removed.push_back("desktop integration");
    return report;
}

void Installer::rollback(const std::string& id) {
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "rollback", mutation_wait_);
    const Registry registry(paths_);
    InstallationRecord record = registry.read_record(id); // NotFoundError

    // Runtime-trust WS4: rollback cannot reactivate a locally blocked App ID,
    // and it fails closed on a corrupt trust record. Every retained version of
    // an app shares the pinned publisher key (install enforces key continuity),
    // so any rollback target is signed by the bound key by construction.
    {
        const std::optional<TrustRecord> rec = TrustStore(paths_).read(id);
        if (rec.has_value() && rec->blocked) {
            throw BlockedKeyError("refusing to roll back " + id +
                                  ": it is locally blocked");
        }
    }

    const std::string current = registry.current_version(id);

    // The newest retained version strictly older than current, under the
    // semver-lite total order (FORMAT-0.1 §8).
    std::optional<std::string> target;
    for (const std::string& version : registry.installed_versions(id)) {
        if (!version_less(version, current)) continue;
        if (!target.has_value() || version_less(*target, version)) {
            target = version;
        }
    }
    if (!target.has_value()) {
        // BusyError -> exit 6, "busy, or an operation conflict". NOT 4.
        //
        // 4 is "not found", and `rollback <typo>` already returns it -- so a
        // script could not tell "fix your App ID" from "this application is
        // installed and there is simply nothing earlier to go back to". Those
        // are different facts with different remedies, and the second one is not
        // an error about the argument at all.
        //
        // Same argument docs/ERRORS.md §6 makes for `install` of an
        // already-current version, and the same conclusion: the requested state
        // already holds, which is an operation conflict. An independent sweep
        // measured this at 4 in 40 of 40 forced `rollback||rollback` races,
        // where the loser is in exactly this position.
        throw BusyError(
            "no previous version of " + id + " to roll back to (current is " +
                current + ")",
            "Nothing changed because there is nowhere to go: this application "
            "is installed and has no retained earlier version. Rollback returns "
            "to the version an update replaced, and only while it is still on "
            "disk -- `lexe gc` removes retained versions. A mistyped App ID "
            "would have exited 4.");
    }

    registry.set_current_version(id, *target);

    // Restore the active-version copies from the per-version meta store so
    // manifest.json/hashes.json keep describing the active version (§9).
    const fs::path app_dir = registry.app_dir(id);
    const fs::path meta = meta_dir(app_dir, *target);
    std::error_code ec;
    if (fs::is_regular_file(meta / "lexe.json", ec)) {
        registry.write_manifest_bytes(id, util::slurp(meta / "lexe.json"));
    }
    if (fs::is_regular_file(meta / "hashes.json", ec)) {
        util::spit(app_dir / "hashes.json", util::slurp(meta / "hashes.json"));
    }

    record.version = *target;
    registry.write_record(record);
}

GcReport Installer::garbage_collect(const std::string& id,
                                    std::size_t keep_previous) {
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "cleanup", mutation_wait_);
    const Registry registry(paths_);

    // NotFoundError when the app is not installed (no active version).
    const std::string active = registry.current_version(id);

    // Deterministic order over all installed versions (semver-lite, §8).
    std::vector<std::string> versions = registry.installed_versions(id);
    std::sort(versions.begin(), versions.end(),
              [](const std::string& a, const std::string& b) {
                  return version_less(a, b);
              });

    // Build the retain set. ALWAYS keep the active version and everything at or
    // newer than it (a rollback target may be newer; forward re-install stays
    // possible). Keep the newest `keep_previous` versions OLDER than active
    // (the rollback-reachable window).
    std::set<std::string> retain;
    retain.insert(active);
    std::vector<std::string> older; // ascending
    for (const std::string& v : versions) {
        if (version_less(v, active)) {
            older.push_back(v);
        } else {
            retain.insert(v); // active or newer — never GC'd
        }
    }
    for (std::size_t i = 0; i < older.size(); ++i) {
        if (older.size() - i <= keep_previous) retain.insert(older[i]);
    }
    // A version referenced by an interrupted transaction must survive so
    // recovery can still complete or roll it back.
    try {
        const TransactionJournal journal = read_journal(paths_, id);
        if (journal.phase != TxnPhase::None && !journal.target_version.empty()) {
            retain.insert(journal.target_version);
        }
    } catch (const Error&) {
        // Unreadable journal: keep the retain set as-is (active + window are
        // already protected); never remove a version we are unsure about.
    }

    GcReport report;
    for (const std::string& v : versions) {
        if (retain.count(v) != 0) {
            report.retained.push_back(v);
            continue;
        }
        // Remove only a version no launch is using. try-exclusive is
        // non-blocking: a held shared lease means a live process → skip it, and
        // keep the exclusive lock across the removal so a launch cannot start
        // on this version mid-delete.
        std::optional<LaunchLease> vlock =
            locks_->try_lock_version_for_gc(id, v);
        if (!vlock.has_value()) {
            report.skipped_in_use.push_back(v);
            continue;
        }
        bool ok = true;
        try {
            util::remove_recursive(registry.version_dir(id, v));
            util::remove_recursive(registry.meta_dir(id, v));
        } catch (...) {
            ok = false; // a failure here never touches the active version
        }
        std::error_code ec;
        if (ok && !fs::exists(registry.version_dir(id, v), ec)) {
            report.removed.push_back(v);
        } else {
            report.failed.push_back(v);
        }
    }
    return report;
}

RepairReport Installer::repair(const std::string& id,
                               const std::optional<fs::path>& package,
                               const RepairOptions& opts) {
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "repair", mutation_wait_);
    const Registry registry(paths_);
    const InstallationRecord record = registry.read_record(id); // NotFoundError
    const std::string current = registry.current_version(id);
    const fs::path app_dir = registry.app_dir(id);
    const fs::path version_dir = registry.version_dir(id, current);

    // §16 "first install / repair": repair is the OTHER place the runtime
    // contract is resolved. Re-resolving here is what makes "install what is
    // missing, then `lexe repair`" a real recovery path for an application
    // whose dependencies stopped being satisfied — and it re-establishes the
    // durable desktop integration at the same time (§14.1).
    {
        InstallationRecord refreshed = record;
        try {
            const Manifest manifest = registry.read_manifest(id);
            resolve_runtime_contract(version_dir, manifest, refreshed);
            registry.write_record(refreshed);
            DesktopIntegration integration(paths_);
            (void)integration.install_runtime_handler();
            (void)integration.install_app(
                manifest, registry.meta_dir(id, current) / "icons");
        } catch (const std::exception&) {
            // Repair must still verify and restore payload files even when
            // the manifest copy or the desktop layer is unavailable.
        }
    }

    // Hash source: the hashes.json copy stored at install time (per-version
    // meta store, falling back to the active-version copy).
    std::error_code ec;
    fs::path hashes_file = meta_dir(app_dir, current) / "hashes.json";
    if (!fs::is_regular_file(hashes_file, ec)) {
        hashes_file = app_dir / "hashes.json";
    }
    if (!fs::is_regular_file(hashes_file, ec)) {
        throw Error("no recorded hashes for " + id + " " + current +
                    "; cannot verify the installation");
    }
    std::vector<PayloadHash> expected = load_payload_hashes(hashes_file);

    // A portable application's recorded set is hashes.json PLUS whatever its
    // build produced (build.json). The compiled entrypoint is not in the
    // package and never was, so leaving it out here would make repair report a
    // healthy installation whose program had been replaced.
    const std::optional<BuildRecord> build_record =
        BuildRecord::load(meta_dir(app_dir, current));
    if (build_record.has_value()) {
        for (const auto& [key, digest] : build_record->products) {
            const std::optional<fs::path> relative = payload_relative(key);
            if (relative.has_value()) expected.push_back({key, *relative, digest});
        }
    }

    RepairReport report;
    const std::vector<PayloadHash> corrupt =
        corrupt_payload_files(version_dir, expected);
    if (corrupt.empty()) {
        report.ok = true;
        return report;
    }

    // Refuse to REWRITE a version something is running.
    //
    // `uninstall` and `garbage_collect` both take an exclusive lock on a version
    // before touching it, precisely because mutating the files of a live
    // application is unsafe. Repair did not, and it restores files by overwriting
    // them in place -- so a running application saw a data file or a library
    // change underneath it, with the same inode, mid-session.
    //
    // The kernel already refuses the worst case: overwriting the ENTRYPOINT of a
    // running process fails with ETXTBSY. Everything else in the payload has no
    // such protection, and that is the reachable hazard: an application that
    // dlopen()s a library or re-reads a data file after repair has replaced it.
    //
    // Checked HERE rather than at the top of the function on purpose. Repair also
    // re-resolves the runtime contract and re-establishes desktop integration,
    // and both are harmless while the application runs -- a blanket refusal would
    // make repair unusable for the case it is most often wanted in. The refusal
    // applies only when there are actually files to restore.
    if (const std::optional<LaunchLease> exclusive =
            locks_->try_lock_version_for_gc(id, current);
        !exclusive.has_value()) {
        throw BusyError(
            "cannot repair " + id + ": version " + current +
                " is currently running, and repairing it means rewriting files "
                "it is using; close it and try again",
            "Stop the application, then re-run `lexe repair " + id + "`.");
    }

    // A package to re-extract from, in order of how well it is known to be the
    // right one:
    //
    //   1. the explicit argument;
    //   2. the source recorded for THIS version in its own meta store;
    //   3. installation.json's `source`, which is where the most recent install
    //      came from.
    //
    // (2) exists because (3) is not version-specific. After install 1.0.0,
    // update to 2.0.0, rollback to 1.0.0, `record.source` still named the 2.0.0
    // package -- and the version check below (correctly) refused to repair 1.0.0
    // from it, so repair failed on an application whose own package was present.
    std::optional<fs::path> pkg = package;
    const bool explicit_package = package.has_value();
    if (!pkg.has_value()) {
        const fs::path per_version = meta_dir(app_dir, current) / "source.txt";
        if (fs::is_regular_file(per_version, ec)) {
            std::string recorded = util::slurp_text(per_version);
            while (!recorded.empty() &&
                   (recorded.back() == '\n' ||
                    recorded.back() == '\r' ||
                    recorded.back() == ' ')) {
                recorded.pop_back();
            }
            const fs::path candidate(recorded);
            if (!recorded.empty() && fs::is_regular_file(candidate, ec)) {
                pkg = candidate;
            }
        }
    }
    if (!pkg.has_value() && !record.source.empty()) {
        const fs::path source(record.source);
        if (fs::is_regular_file(source, ec)) pkg = source;
    }

    if (pkg.has_value()) {
        try {
            // Nothing is copied out of the package before it passes §6 in
            // full, and it must be exactly the installed release: same id,
            // same version, signed with the pinned publisher key.
            const Manifest m = verify_package_or_throw(*pkg, false);
            if (m.id != id || m.version != current ||
                !crypto::same_public_key(m.publisher_public_key,
                                         record.publisher_key)) {
                throw Error("package " + pkg->string() + " is not " + id + " " +
                            current +
                            " signed with the pinned publisher key; cannot "
                            "repair from it");
            }
            const PackageReader reader(*pkg);
            const fs::path staging = app_dir / ".staging-repair";
            util::remove_recursive(staging);
            try {
                // Full zip-slip-safe extraction (restores POSIX exec bits),
                // then copy only the damaged files into place.
                reader.extract_payload(staging);
                for (const PayloadHash& entry : corrupt) {
                    const fs::path from = staging / entry.relative;
                    std::error_code file_ec;
                    if (!fs::is_regular_file(from, file_ec)) {
                        continue; // absent from the package: stays corrupt
                    }
                    const std::optional<fs::path> to =
                        contained_destination(version_dir, entry.relative);
                    if (!to.has_value()) {
                        // See contained_destination: a destination that resolves
                        // outside the version directory is reported, not written
                        // and not silently skipped.
                        report.corrupt_files.push_back(
                            entry.key + " (its destination resolves outside " +
                            version_dir.string() +
                            ", most likely through a symlink; refusing to write "
                            "there)");
                        continue;
                    }
                    fs::create_directories(to->parent_path());
                    fs::copy_file(from, *to,
                                  fs::copy_options::overwrite_existing);
                    report.repaired_files.push_back(entry.key);
                }
                // A portable application cannot be repaired by copying: the
                // file that is damaged is the one the package never contained.
                // Repairing it means building it again, which is the same
                // operation the install performed and needs the same explicit
                // approval — the alternative would be a repair command that
                // silently compiles code.
                if (m.application_kind == ApplicationType::Portable &&
                    build_record.has_value()) {
                    bool product_damaged = false;
                    for (const PayloadHash& entry : corrupt) {
                        if (build_record->products.count(entry.key) != 0) {
                            product_damaged = true;
                        }
                    }
                    if (product_damaged && !opts.approve_compile) {
                        throw PermissionError(
                            "repairing " + id +
                                " means compiling its source again — its "
                                "entrypoint is built on this machine, not "
                                "carried in the package — and that was not "
                                "approved",
                            "Re-run with `--approve-compile`.");
                    }
                    if (product_damaged) {
                        CompileRequest request;
                        request.manifest = m;
                        request.build_tree = staging;
                        request.scratch_dir = app_dir / ".repair-scratch";
                        request.approval = CompileApproval::grant();
                        const CompileResult built =
                            compile_for_host(paths_, request);
                        util::remove_recursive(request.scratch_dir);
                        if (!built.ok) {
                            throw CompileError(built.failure, built.hint);
                        }
                        for (const auto& [key, digest] : built.record.products) {
                            const std::optional<fs::path> relative =
                                payload_relative(key);
                            if (!relative.has_value()) continue;
                            const fs::path from = staging / *relative;
                            std::error_code build_ec;
                            if (!fs::is_regular_file(from, build_ec)) continue;
                            const std::optional<fs::path> to =
                                contained_destination(version_dir, *relative);
                            if (!to.has_value()) {
                                report.corrupt_files.push_back(
                                    key + " (its destination resolves outside " +
                                    version_dir.string() + ")");
                                continue;
                            }
                            fs::create_directories(to->parent_path());
                            fs::copy_file(from, *to,
                                          fs::copy_options::overwrite_existing);
                            report.repaired_files.push_back(key);
                        }
                        built.record.save(meta_dir(app_dir, current));
                        // The freshly built product has a new hash; judge the
                        // installation against what was actually just built.
                        for (PayloadHash& entry : expected) {
                            const auto it =
                                built.record.products.find(entry.key);
                            if (it != built.record.products.end()) {
                                entry.digest = it->second;
                            }
                        }
                    }
                }
            } catch (...) {
                util::remove_recursive(staging);
                throw;
            }
            util::remove_recursive(staging);
#ifndef _WIN32
            // A repaired entrypoint must come back executable, same as at
            // install time.
            ensure_entrypoint_executable(version_dir, m.entrypoint_executable);
#endif
        } catch (const PermissionError&) {
            // Not "the cached package turned out unusable": the user asked for
            // a repair, this one needs a compile, and the compile was not
            // approved. Swallowing that would report the application as
            // unrepairable when the remedy is one flag away.
            throw;
        } catch (const CompileError&) {
            throw; // likewise: we know exactly why it cannot be repaired
        } catch (const Error& e) {
            if (explicit_package) throw;
            // The cached source turned out unusable — report health only, but
            // KEEP the reason. Discarding it is what made a tampered local
            // record and a foreign-key source arrive as the same sentence.
            report.blocked_reason = e.what();
            report.blocked_hint = e.hint();
            report.repaired_files.clear();
        }
    }

    // APPENDED, not assigned. The restore loop records destinations it refused
    // to write (see contained_destination), and assigning here discarded them --
    // so a refusal that mattered was replaced by the digest scan's own list.
    for (const std::string& key :
         keys_of(corrupt_payload_files(version_dir, expected))) {
        if (std::find(report.corrupt_files.begin(), report.corrupt_files.end(),
                      key) == report.corrupt_files.end()) {
            report.corrupt_files.push_back(key);
        }
    }
    report.ok = report.corrupt_files.empty();
    return report;
}

} // namespace lexe
