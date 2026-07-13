// verify — the FORMAT-0.1 §6 verification pipeline, in normative order:
//   1 "structure"           archive opens; §2 entry rules; required entries
//   2 "manifest"            lexe.json parses; §5 constraints hold
//   3 "key"                 publisher.publicKey decodes per §4
//   4 "manifest-signature"  manifest.sig over the EXACT stored lexe.json bytes
//   5 "payload-signature"   payload.sig over the EXACT stored hashes.json bytes
//   6 "hashes"              §3 set equality (both directions) + per-entry SHA-256
//   7 "compatibility"       (install/update only) host arch ∈ architectures
// Signatures are checked over the exact stored entry bytes (§4) — no JSON
// canonicalization anywhere. The pipeline stops at the first failing stage;
// stages after it are absent from the report (verify.hpp contract).

#include "core/verify.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/package.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace lexe {

namespace {

// Stage names (verify.hpp / FORMAT-0.1 §6).
constexpr const char* kStructure = "structure";
constexpr const char* kManifest = "manifest";
constexpr const char* kKey = "key";
constexpr const char* kManifestSignature = "manifest-signature";
constexpr const char* kPayloadSignature = "payload-signature";
constexpr const char* kHashes = "hashes";
constexpr const char* kCompatibility = "compatibility";

void pass(VerificationReport& report, const char* name, std::string detail) {
    report.stages.push_back({name, true, std::move(detail)});
}

void fail(VerificationReport& report, const char* name, std::string detail) {
    report.stages.push_back({name, false, std::move(detail)});
}

std::string join(const std::vector<std::string>& parts, const char* separator) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) out += separator;
        out += parts[i];
    }
    return out;
}

/// Stages 4/5 core: `sig_bytes` must be a raw 64-byte Ed25519 signature that
/// verifies over the exact stored `message` bytes (FORMAT-0.1 §4). Returns
/// the failure reason, or nullopt when the signature is good.
std::optional<std::string>
signature_problem(const std::vector<std::uint8_t>& sig_bytes,
                  const std::vector<std::uint8_t>& message,
                  const crypto::PublicKey& publisher_key,
                  const char* sig_entry, const char* covered_entry) {
    crypto::Signature sig{};
    if (sig_bytes.size() != sig.size()) {
        return std::string(sig_entry) +
               " must be a raw 64-byte Ed25519 signature, got " +
               std::to_string(sig_bytes.size()) + " bytes";
    }
    std::copy(sig_bytes.begin(), sig_bytes.end(), sig.begin());
    if (!crypto::verify_signature(message, sig, publisher_key)) {
        return std::string(sig_entry) +
               " does not verify over the exact stored " + covered_entry +
               " bytes with the publisher key";
    }
    return std::nullopt;
}

/// Whether `entry_path` is excluded from hashes.json coverage (FORMAT-0.1 §3):
/// lexe.json, metadata/hashes.json itself, and everything under signatures/.
bool excluded_from_coverage(const std::string& entry_path) {
    return entry_path == "lexe.json" || entry_path == "metadata/hashes.json" ||
           entry_path.rfind("signatures/", 0) == 0;
}

/// Stage 6 core (FORMAT-0.1 §3): parse hashes.json, enforce
/// algorithm == "sha256", check `files` against the archive with set equality
/// in BOTH directions, and verify every covered entry's SHA-256. Returns all
/// problems found (empty means the stage passed); sets `covered_count` for
/// the success detail.
std::vector<std::string>
hash_problems(const PackageReader& reader,
              const std::vector<std::uint8_t>& hashes_bytes,
              std::size_t& covered_count) {
    std::vector<std::string> problems;
    covered_count = 0;

    const nlohmann::json doc = nlohmann::json::parse(
        hashes_bytes.begin(), hashes_bytes.end(), nullptr,
        /*allow_exceptions=*/false);
    if (doc.is_discarded() || !doc.is_object()) {
        problems.push_back("metadata/hashes.json is not a JSON object");
        return problems;
    }
    const auto algorithm = doc.find("algorithm");
    if (algorithm == doc.end() || !algorithm->is_string() ||
        algorithm->get<std::string>() != "sha256") {
        problems.push_back(
            "metadata/hashes.json \"algorithm\" must be the string \"sha256\"");
        return problems;
    }
    const auto files = doc.find("files");
    if (files == doc.end() || !files->is_object()) {
        problems.push_back(
            "metadata/hashes.json \"files\" must be a JSON object");
        return problems;
    }

    // The set the archive says must be covered (§3): every entry except the
    // exclusions above.
    std::set<std::string> should_cover;
    for (const PackageEntry& e : reader.entries()) {
        if (!excluded_from_coverage(e.path)) should_cover.insert(e.path);
    }

    // The set hashes.json actually covers.
    std::set<std::string> covered;
    for (const auto& item : files->items()) {
        if (!item.value().is_string()) {
            problems.push_back("digest for \"" + item.key() +
                               "\" must be a hex string");
            continue;
        }
        covered.insert(item.key());
    }

    // Set equality, direction 1: everything covered must be a coverable
    // archive entry.
    for (const std::string& path : covered) {
        if (should_cover.count(path) != 0) continue;
        if (reader.has_entry(path)) {
            problems.push_back("hashes.json must not cover \"" + path +
                               "\" (excluded by §3)");
        } else {
            problems.push_back("covered entry missing from archive: " + path);
        }
    }
    // Set equality, direction 2: every coverable archive entry must be
    // covered.
    for (const std::string& path : should_cover) {
        if (covered.count(path) == 0) {
            problems.push_back("archive entry not covered by hashes.json: " +
                               path);
        }
    }

    // Digest checks over the intersection. Digests are lowercase hex (§3);
    // exact string comparison enforces that too.
    for (const std::string& path : should_cover) {
        if (covered.count(path) == 0) continue;
        const std::string expected = files->at(path).get<std::string>();
        const std::string actual = crypto::sha256_hex(reader.read_entry(path));
        if (expected != actual) {
            problems.push_back("SHA-256 mismatch for \"" + path +
                               "\": hashes.json says " + expected +
                               ", entry hashes to " + actual);
        }
    }

    covered_count = should_cover.size();
    return problems;
}

/// Full pipeline run: the report plus (once stage 2 passed) the parsed
/// manifest, so verify_package_or_throw does not parse twice.
struct PipelineOutcome {
    VerificationReport report;
    std::optional<Manifest> manifest;
};

PipelineOutcome run_pipeline(const fs::path& lexe_file,
                             bool check_architecture) {
    PipelineOutcome out;
    VerificationReport& report = out.report;

    // ---- stage 1: structure (§2) --------------------------------------
    // PackageReader enforces every §2 rule (path safety, no symlinks, no
    // duplicates, required entries present). The four control entries are
    // read here as well so ZIP data corruption of a required entry is a
    // structure failure, not a later-stage surprise.
    std::optional<PackageReader> reader;
    std::vector<std::uint8_t> manifest_bytes;
    std::vector<std::uint8_t> hashes_bytes;
    std::vector<std::uint8_t> manifest_sig;
    std::vector<std::uint8_t> payload_sig;
    try {
        reader.emplace(lexe_file);
        manifest_bytes = reader->read_entry("lexe.json");
        hashes_bytes = reader->read_entry("metadata/hashes.json");
        manifest_sig = reader->read_entry("signatures/manifest.sig");
        payload_sig = reader->read_entry("signatures/payload.sig");
    } catch (const Error& e) {
        // NotFoundError (no such file) and VerificationError (bad archive)
        // both land here: verify_package never throws for a failing package.
        fail(report, kStructure, e.what());
        return out;
    }
    pass(report, kStructure,
         "archive OK: " + std::to_string(reader->entries().size()) +
             " entries, §2 path rules hold, required entries present");

    // ---- stage 2: manifest (§5) ----------------------------------------
    Manifest manifest;
    try {
        manifest = Manifest::parse(manifest_bytes);
    } catch (const Error& e) {
        fail(report, kManifest, e.what());
        return out;
    }
    pass(report, kManifest,
         "lexe.json is a valid 0.1 manifest: " + manifest.id + " " +
             manifest.version + " (\"" + manifest.name + "\")");
    out.manifest = manifest;

    // ---- stage 3: key decode (§4) ---------------------------------------
    crypto::PublicKey publisher_key{};
    try {
        publisher_key = crypto::decode_public_key(manifest.publisher_public_key);
    } catch (const Error& e) {
        fail(report, kKey, e.what());
        return out;
    }
    pass(report, kKey,
         "publisher.publicKey decodes to a 32-byte Ed25519 key (" +
             manifest.publisher_name + ")");

    // ---- stage 4: manifest signature (§4) -------------------------------
    if (const auto problem =
            signature_problem(manifest_sig, manifest_bytes, publisher_key,
                              "signatures/manifest.sig", "lexe.json")) {
        fail(report, kManifestSignature, *problem);
        return out;
    }
    pass(report, kManifestSignature,
         "signatures/manifest.sig verifies over the stored lexe.json bytes (" +
             std::to_string(manifest_bytes.size()) + " bytes)");

    // ---- stage 5: payload signature (§4) --------------------------------
    if (const auto problem = signature_problem(
            payload_sig, hashes_bytes, publisher_key,
            "signatures/payload.sig", "metadata/hashes.json")) {
        fail(report, kPayloadSignature, *problem);
        return out;
    }
    pass(report, kPayloadSignature,
         "signatures/payload.sig verifies over the stored "
         "metadata/hashes.json bytes (" +
             std::to_string(hashes_bytes.size()) + " bytes)");

    // ---- stage 6: hashes (§3) -------------------------------------------
    std::size_t covered_count = 0;
    try {
        const std::vector<std::string> problems =
            hash_problems(*reader, hashes_bytes, covered_count);
        if (!problems.empty()) {
            fail(report, kHashes, join(problems, "; "));
            return out;
        }
    } catch (const Error& e) {
        // e.g. a covered entry whose compressed data is corrupt.
        fail(report, kHashes, e.what());
        return out;
    }
    pass(report, kHashes,
         "all " + std::to_string(covered_count) +
             " covered entries present, coverage is exact (both directions), "
             "every SHA-256 digest matches");

    // ---- stage 7: compatibility (§6.7, install/update only) --------------
    if (check_architecture) {
        const std::string host = host_architecture();
        const bool supported =
            std::find(manifest.architectures.begin(),
                      manifest.architectures.end(),
                      host) != manifest.architectures.end();
        if (!supported) {
            fail(report, kCompatibility,
                 "host architecture " + host +
                     " is not supported by this package (architectures: " +
                     join(manifest.architectures, ", ") + ")");
            return out;
        }
        pass(report, kCompatibility,
             "host architecture " + host + " is listed in the manifest");
    }

    return out;
}

} // namespace

std::string host_architecture() {
#if defined(_M_ARM64) || defined(__aarch64__)
    return "aarch64";
#elif defined(_M_X64) || defined(__x86_64__) || defined(__amd64__)
    return "x86_64";
#else
    // Never matches a recognised manifest architecture (FORMAT-0.1 §5), so
    // the compatibility stage fails with an honest explanation.
    return "unknown";
#endif
}

VerificationReport verify_package(const fs::path& lexe_file,
                                  bool check_architecture) {
    return run_pipeline(lexe_file, check_architecture).report;
}

Manifest verify_package_or_throw(const fs::path& lexe_file,
                                 bool check_architecture) {
    PipelineOutcome out = run_pipeline(lexe_file, check_architecture);
    if (!out.report.ok()) {
        const VerificationStage* failure = out.report.first_failure();
        // ok() is false only when a present stage failed (the pipeline always
        // records at least the structure stage), so failure is non-null.
        throw VerificationError("verification failed at stage \"" +
                                failure->name + "\": " + failure->detail);
    }
    return std::move(*out.manifest);
}

} // namespace lexe
