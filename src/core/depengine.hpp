#pragma once
// depengine — the automatic dependency-resolution engine (Phase 2 / DX3). Given
// an application's main ELF binary it recursively discovers the shared-library
// dependency graph by reading ELF metadata DIRECTLY (core/elf.hpp — never ldd),
// resolves each DT_NEEDED soname against the host + payload search paths,
// classifies it (host interface / bundle / forbidden / unresolved / language
// runtime), hashes bundled files, tracks versioned requirements, and handles
// duplicates and cycles.
//
// The classification is what makes the builder able to recommend handling
// without the developer understanding the internals: most dependencies resolve
// to "provided by the host" or "bundle this", and only the unusual ones raise a
// warning that explains WHY.

#include "core/elf.hpp"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace lexe {

/// How a dependency should be handled.
enum class DependencyKind {
    HostInterface,   // provided by every conforming host — do NOT bundle
    Bundle,          // an ordinary library — recommend bundling into the payload
    Forbidden,       // must come from the host (driver/GPU) — must NOT be bundled
    Unresolved,      // a DT_NEEDED soname that could not be found anywhere
    LanguageRuntime, // owned by a language-runtime hook (future; DX3 extension)
};
const char* to_string(DependencyKind k);

/// One node of the resolved dependency graph.
struct Dependency {
    std::string soname;                    // e.g. "libssl.so.3"
    std::filesystem::path resolved_path;   // where it was found ("" if not)
    DependencyKind kind = DependencyKind::Unresolved;
    std::string reason;                    // why it was classified this way
    std::string recommendation;            // recommended handling, in plain words
    std::string sha256;                    // set only for a resolved bundle file
    elf::Machine machine = elf::Machine::Unknown; // arch of the resolved file
    std::vector<std::string> needed_by;    // sonames/root that depend on it
    std::vector<std::string> version_needs;// versioned reqs of THIS object
};

/// The full dependency analysis of one root binary.
struct DependencyReport {
    std::filesystem::path root;
    elf::ElfInfo root_info;                // arch/type/interpreter/version-needs
    std::vector<Dependency> dependencies;  // deduped, sorted by soname
    std::vector<std::string> cycles;       // "a -> b -> a" descriptions (rare)

    std::size_t count(DependencyKind k) const;
    std::vector<const Dependency*> of_kind(DependencyKind k) const;
    bool has_unresolved() const { return count(DependencyKind::Unresolved) > 0; }
    bool has_forbidden() const { return count(DependencyKind::Forbidden) > 0; }
    /// The highest "GLIBC_x.y" requirement across the whole graph (root + deps),
    /// e.g. "2.34"; empty when none is present.
    std::string max_glibc_version() const;
    /// Every versioned requirement across the graph, deduped and sorted.
    std::vector<std::string> all_version_needs() const;
};

/// Tuning for a dependency analysis.
struct DependencyOptions {
    /// Directories searched BEFORE the host system paths — normally the payload
    /// directory and its subdirectories (the app's own bundled libraries).
    std::vector<std::filesystem::path> payload_search_paths;
    /// Additional host library directories to search (beyond the arch defaults).
    std::vector<std::filesystem::path> extra_search_paths;
    /// Recurse into resolved bundle libraries (default true).
    bool recurse = true;
    /// Compute SHA-256 for resolved bundle files (default true).
    bool hash_bundles = true;
    /// Cap on graph size, a safety bound against pathological inputs.
    std::size_t max_nodes = 4096;
};

/// Analyze the dependency graph of `root`. Never throws for a non-ELF or
/// unreadable root — the report's root_info.is_elf is false and dependencies is
/// empty. Reads ELF metadata directly; resolution is deterministic (it does not
/// consult LD_LIBRARY_PATH).
DependencyReport analyze_dependencies(const std::filesystem::path& root,
                                      const DependencyOptions& opts = {});

/// The default host library search directories for a machine (multiarch triplet
/// + lib/lib64), exposed for tests and for the compatibility layer.
std::vector<std::filesystem::path> default_search_dirs(elf::Machine machine);

// --- language-runtime extension interface (DX3; no language implemented yet) --

/// A hook that contributes language-specific runtime dependencies (Python,
/// Java, Node, …). None are implemented in this phase; the registry exists so
/// they can be added without touching the core engine.
class LanguageRuntimeHook {
public:
    virtual ~LanguageRuntimeHook() = default;
    virtual std::string language() const = 0;
    /// Detect language-runtime dependencies of `root`; return {} when this hook
    /// does not apply.
    virtual std::vector<Dependency> detect(
        const std::filesystem::path& root, const DependencyOptions& opts) const = 0;
};

/// Register a language-runtime hook (consulted by analyze_dependencies).
void register_language_hook(std::shared_ptr<LanguageRuntimeHook> hook);
/// The registered hooks (for tests/introspection).
const std::vector<std::shared_ptr<LanguageRuntimeHook>>& language_hooks();

} // namespace lexe
