// depengine — see depengine.hpp. Direct-ELF dependency resolution + typed
// classification. Resolution is deterministic and read-only.

#include "lexe/analysis/depengine.hpp"

#include "lexe/package/crypto.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <set>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace lexe {
namespace fs = std::filesystem;

const char* to_string(DependencyKind k) {
    switch (k) {
    case DependencyKind::HostInterface:   return "host-interface";
    case DependencyKind::Bundle:          return "bundle";
    case DependencyKind::Forbidden:       return "forbidden";
    case DependencyKind::Unresolved:      return "unresolved";
    case DependencyKind::LanguageRuntime: return "language-runtime";
    }
    return "unresolved";
}

const char* to_string(DependencyOrigin o) {
    switch (o) {
    case DependencyOrigin::None:      return "none";
    case DependencyOrigin::Payload:   return "payload";
    case DependencyOrigin::System:    return "system";
    case DependencyOrigin::Elsewhere: return "elsewhere";
    }
    return "none";
}

namespace {

// The core glibc / toolchain runtime present on every conforming Linux host.
// These are the "host interface" and must NOT be bundled (bundling libc or the
// loader breaks the ABI contract with the host kernel + loader).
bool is_host_interface(const std::string& soname) {
    static const std::set<std::string_view> kHost = {
        "libc.so.6",      "libm.so.6",       "libdl.so.2",
        "libpthread.so.0","librt.so.1",      "libutil.so.1",
        "libresolv.so.2", "libgcc_s.so.1",   "libanl.so.1",
        "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1",
        "ld-linux-riscv64-lp64d.so.1", "ld-linux.so.2",
        "linux-vdso.so.1", "linux-gate.so.1",
    };
    if (kHost.count(soname) != 0) return true;
    // Any ld-linux* loader variant is a host interface.
    return soname.rfind("ld-linux", 0) == 0;
}

// Libraries that MUST come from the host and must never be bundled: the GPU /
// graphics / accelerator driver interfaces. Bundling them breaks the driver
// contract; the target host must provide them (driver passthrough).
bool is_forbidden_bundle(const std::string& soname, std::string& why) {
    static const std::array<std::string_view, 12> kPrefixes = {
        "libGL.so",   "libGLX.so",    "libGLdispatch.so", "libEGL.so",
        "libGLESv2.so","libOpenGL.so","libcuda.so",       "libnvidia-",
        "libvulkan.so","libdrm.so",   "libva.so",         "libnvcuvid.so",
    };
    for (const std::string_view& p : kPrefixes) {
        if (soname.rfind(std::string(p), 0) == 0) {
            why = "a host GPU/graphics/accelerator driver interface";
            return true;
        }
    }
    return false;
}

std::string multiarch_triplet(elf::Machine m) {
    switch (m) {
    case elf::Machine::X86_64:  return "x86_64-linux-gnu";
    case elf::Machine::AArch64: return "aarch64-linux-gnu";
    case elf::Machine::RiscV:   return "riscv64-linux-gnu";
    case elf::Machine::Arm:     return "arm-linux-gnueabihf";
    default:                    return "";
    }
}

/// Expand $ORIGIN in an RPATH/RUNPATH entry relative to the object's directory.
fs::path expand_origin(const std::string& entry, const fs::path& object_dir) {
    const std::string kOrigin = "$ORIGIN";
    if (entry.rfind(kOrigin, 0) == 0) {
        return object_dir / fs::path("." + entry.substr(kOrigin.size()));
    }
    return fs::path(entry);
}

// Language-runtime hook registry (empty in this phase).
std::vector<std::shared_ptr<LanguageRuntimeHook>>& hooks() {
    static std::vector<std::shared_ptr<LanguageRuntimeHook>> registry;
    return registry;
}

} // namespace

std::vector<fs::path> default_search_dirs(elf::Machine machine) {
    std::vector<fs::path> dirs;
    const std::string triplet = multiarch_triplet(machine);
    if (!triplet.empty()) {
        dirs.emplace_back(fs::path("/lib") / triplet);
        dirs.emplace_back(fs::path("/usr/lib") / triplet);
    }
    for (const char* d : {"/lib64", "/usr/lib64", "/lib", "/usr/lib",
                          "/usr/local/lib"}) {
        dirs.emplace_back(d);
    }
    return dirs;
}

void register_language_hook(std::shared_ptr<LanguageRuntimeHook> hook) {
    if (hook) hooks().push_back(std::move(hook));
}
const std::vector<std::shared_ptr<LanguageRuntimeHook>>& language_hooks() {
    return hooks();
}

std::size_t DependencyReport::count(DependencyKind k) const {
    std::size_t n = 0;
    for (const Dependency& d : dependencies) {
        if (d.kind == k) ++n;
    }
    return n;
}

std::vector<const Dependency*> DependencyReport::of_kind(DependencyKind k) const {
    std::vector<const Dependency*> out;
    for (const Dependency& d : dependencies) {
        if (d.kind == k) out.push_back(&d);
    }
    return out;
}

std::vector<std::string> DependencyReport::all_version_needs() const {
    std::set<std::string> set(root_info.version_needs.begin(),
                              root_info.version_needs.end());
    for (const Dependency& d : dependencies) {
        set.insert(d.version_needs.begin(), d.version_needs.end());
    }
    return std::vector<std::string>(set.begin(), set.end());
}

std::string DependencyReport::max_glibc_version() const {
    int best_major = -1, best_minor = -1;
    const auto consider = [&](const std::vector<std::string>& needs) {
        for (const std::string& v : needs) {
            if (v.rfind("GLIBC_", 0) != 0) continue;
            const std::string num = v.substr(6);
            const std::size_t dot = num.find('.');
            if (dot == std::string::npos) continue;
            try {
                const int major = std::stoi(num.substr(0, dot));
                const int minor = std::stoi(num.substr(dot + 1));
                if (major > best_major ||
                    (major == best_major && minor > best_minor)) {
                    best_major = major;
                    best_minor = minor;
                }
            } catch (const std::exception&) {
            }
        }
    };
    // The package = the executable + everything it ships. Host-interface
    // libraries are deliberately excluded: the target host supplies its own
    // matching libc/libm, and the BUILD host's copies carry their own internal
    // GLIBC_x.y needs that have nothing to do with this application. Including
    // them made the same package report a different requirement on every
    // distribution it was analyzed on.
    consider(root_info.version_needs);
    for (const Dependency& d : dependencies) {
        if (d.kind == DependencyKind::Bundle) consider(d.version_needs);
    }
    if (best_major < 0) return "";
    return std::to_string(best_major) + "." + std::to_string(best_minor);
}

namespace {

/// Resolve a soname to a file under an ordered set of directories.
fs::path resolve(const std::string& soname, const std::vector<fs::path>& dirs) {
    // A name with a '/' is a PATH, not a library to search for, and the object
    // being analysed may be untrusted: `dir / "/etc/passwd"` is "/etc/passwd",
    // and "../x" walks out of dir. Looking either up would let a package make
    // `lexe inspect` open and hash host files of its choosing. Unresolved, and
    // the filesystem is not touched. ("." and ".." are directories anyway.)
    if (soname.empty() || soname.find('/') != std::string::npos ||
        soname == "." || soname == "..") {
        return {};
    }
    std::error_code ec;
    for (const fs::path& dir : dirs) {
        const fs::path candidate = dir / soname;
        if (fs::is_regular_file(candidate, ec)) {
            return candidate;
        }
    }
    return {};
}

/// Is `file` inside any of `roots`?
bool under_any(const fs::path& file, const std::vector<fs::path>& roots) {
    if (file.empty()) return false;
    std::error_code ec;
    const fs::path canon = fs::weakly_canonical(file, ec);
    const fs::path target = ec ? file : canon;
    for (const fs::path& root : roots) {
        if (root.empty()) continue;
        std::error_code rec;
        const fs::path rcanon = fs::weakly_canonical(root, rec);
        const fs::path base = rec ? root : rcanon;
        const fs::path rel = target.lexically_relative(base);
        if (rel.empty() || rel == fs::path(".")) continue;
        if (rel.begin() == rel.end()) continue;
        if (rel.begin()->string() == "..") continue;
        return true;
    }
    return false;
}

/// Classify WHERE a resolved library was found — see DependencyOrigin. The
/// payload wins over the system directories, because a package that carries its
/// own copy is using that copy.
DependencyOrigin origin_of(const fs::path& resolved,
                           const DependencyOptions& opts,
                           elf::Machine machine,
                           const std::vector<fs::path>& origin_relative_dirs) {
    if (resolved.empty()) return DependencyOrigin::None;
    // An $ORIGIN-relative rpath travels WITH the binary. It resolves against
    // wherever the object happens to be, which means it resolves inside the
    // sandbox exactly as it does here -- it is the precise opposite of a
    // host-only path, and it is the idiom this runtime documents and recommends.
    //
    // Classifying it as Elsewhere was a false negative of the worst kind: a
    // package using the CORRECT relocatable idiom was reported as unable to
    // start. Caught by building the three shapes and checking each against
    // whether it actually runs, rather than against what the code implied.
    if (under_any(resolved, origin_relative_dirs)) {
        return DependencyOrigin::Payload;
    }
    if (under_any(resolved, opts.payload_search_paths)) {
        return DependencyOrigin::Payload;
    }
    if (under_any(resolved, default_search_dirs(machine))) {
        return DependencyOrigin::System;
    }
    return DependencyOrigin::Elsewhere;
}

struct Resolver {
    const DependencyOptions& opts;
    DependencyReport& report;
    std::unordered_map<std::string, std::size_t> index; // soname -> deps index
    std::unordered_set<std::string> on_path;            // DFS stack for cycles

    void classify(Dependency& d, const std::string& soname,
                  const fs::path& resolved) {
        std::string why;
        if (is_host_interface(soname)) {
            d.kind = DependencyKind::HostInterface;
            d.reason = "part of the core system runtime present on every "
                       "conforming Linux host";
            d.recommendation = "Rely on the host — do not bundle.";
        } else if (is_forbidden_bundle(soname, why)) {
            d.kind = DependencyKind::Forbidden;
            d.reason = why + "; it must be provided by the target host";
            d.recommendation =
                "Do NOT bundle. The application requires host driver passthrough.";
        } else if (!resolved.empty()) {
            d.kind = DependencyKind::Bundle;
            d.reason = "an ordinary shared library not guaranteed on every host";
            d.recommendation = "Bundle it into the application for portability.";
        } else {
            d.kind = DependencyKind::Unresolved;
            d.reason = "the soname could not be found in the payload or on this "
                       "build host";
            d.recommendation =
                "Provide the library in the payload, or confirm the target host "
                "supplies it.";
        }
    }

    // Build the ordered search dirs for an object being processed.
    //
    // Two shapes, because there are two questions -- see
    // DependencyOptions::runtime_contract. The advisory shape may look straight
    // into the payload; the runtime shape may not, because the dynamic loader
    // cannot. The ONLY way the payload is reachable at launch is through an
    // $ORIGIN-relative DT_RPATH/DT_RUNPATH, and that is expanded below either
    // way, so a correctly linked package resolves identically under both.
    std::vector<fs::path> search_dirs(const elf::ElfInfo& info,
                                      const fs::path& object_dir) {
        std::vector<fs::path> dirs;
        if (!opts.runtime_contract) {
            dirs = opts.payload_search_paths;
        }
        for (const std::string& e : info.runpath) {
            dirs.push_back(expand_origin(e, object_dir));
        }
        for (const std::string& e : info.rpath) {
            dirs.push_back(expand_origin(e, object_dir));
        }
        if (!opts.runtime_contract) {
            for (const fs::path& p : opts.extra_search_paths) dirs.push_back(p);
        }
        const std::vector<fs::path> sys = default_search_dirs(info.machine);
        dirs.insert(dirs.end(), sys.begin(), sys.end());
        return dirs;
    }

    /// The directories a SANDBOXED launch will actually be able to search: the
    /// package's own content, and the read-only system view the sandbox mounts.
    ///
    /// Deliberately excludes DT_RPATH / DT_RUNPATH and any caller-supplied extra
    /// paths, because those can name directories that exist only on the machine
    /// running this analysis.
    /// The directories this object's own DT_RPATH/DT_RUNPATH name RELATIVE to
    /// itself. These move with the binary, so they are part of the package.
    std::vector<fs::path> origin_relative_dirs(const elf::ElfInfo& info,
                                               const fs::path& object_dir) {
        std::vector<fs::path> dirs;
        for (const std::vector<std::string>* list : {&info.runpath, &info.rpath}) {
            for (const std::string& e : *list) {
                if (e.rfind("$ORIGIN", 0) != 0) continue;
                dirs.push_back(expand_origin(e, object_dir));
            }
        }
        return dirs;
    }

    std::vector<fs::path> sandbox_search_dirs(const elf::ElfInfo& info) {
        std::vector<fs::path> dirs;
        // Same split as search_dirs: under the runtime question the payload is
        // not implicitly searchable, so the fallback may only consider what the
        // loader would actually reach.
        if (!opts.runtime_contract) dirs = opts.payload_search_paths;
        const std::vector<fs::path> sys = default_search_dirs(info.machine);
        dirs.insert(dirs.end(), sys.begin(), sys.end());
        return dirs;
    }

    void visit(const fs::path& object, const elf::ElfInfo& info,
               const std::string& self_label) {
        if (report.dependencies.size() >= opts.max_nodes) return;
        const fs::path object_dir = object.has_parent_path()
                                        ? object.parent_path()
                                        : fs::current_path();
        const std::vector<fs::path> dirs = search_dirs(info, object_dir);

        for (const std::string& soname : info.needed) {
            const auto existing = index.find(soname);
            if (existing != index.end()) {
                // Already discovered — record the extra dependant, and note a
                // cycle if this needed soname is an ancestor on the DFS path.
                Dependency& dep = report.dependencies[existing->second];
                if (std::find(dep.needed_by.begin(), dep.needed_by.end(),
                              self_label) == dep.needed_by.end()) {
                    dep.needed_by.push_back(self_label);
                }
                if (on_path.count(soname) != 0) {
                    report.cycles.push_back(self_label + " -> " + soname +
                                            " (already on the path)");
                }
                continue;
            }
            if (report.dependencies.size() >= opts.max_nodes) return;

            const fs::path resolved = resolve(soname, dirs);
            Dependency dep;
            dep.soname = soname;
            dep.resolved_path = resolved;
            dep.needed_by.push_back(self_label);
            classify(dep, soname, resolved);

            elf::ElfInfo child_info;
            if (!resolved.empty()) {
                child_info = elf::read(resolved);
                dep.machine = child_info.machine;
                // Recorded from the machine of the file actually found, so a
                // wrong-arch library cannot be filed under the wrong origin.
                const std::vector<fs::path> own_origin_dirs =
                    origin_relative_dirs(info, object_dir);
                dep.origin = origin_of(resolved, opts, child_info.machine,
                                       own_origin_dirs);

                // If it was found only through a path the sandbox will not have,
                // ask the question that actually matters -- CAN THE SANDBOX
                // SATISFY THIS SONAME? -- and if it can, report what the sandbox
                // will use.
                //
                // Getting this wrong made the runtime refuse a package it could
                // have run. The first version treated "resolved via a host-only
                // rpath" as unsatisfiable, which is false whenever the same
                // soname also sits in /usr: the loader inside the sandbox finds
                // the rpath directory missing and falls through to the default
                // paths, exactly as it does when the rpath dangles.
                //
                // The proof that it was a defect rather than a policy was an
                // inconsistency, and it is worth keeping in view: a DANGLING
                // absolute rpath was already accepted and ran, so the runtime
                // had always considered "rpath unavailable, resolve from /usr"
                // acceptable. It refused only when the rpath directory happened
                // to EXIST on the build machine -- a property of the build
                // machine with no bearing on what the sandbox can do. The same
                // package, byte for byte, installed or refused depending on a
                // directory outside it.
                if (dep.origin == DependencyOrigin::Elsewhere) {
                    const fs::path in_sandbox =
                        resolve(soname, sandbox_search_dirs(info));
                    if (!in_sandbox.empty()) {
                        const elf::ElfInfo sandbox_info = elf::read(in_sandbox);
                        dep.resolved_path = in_sandbox;
                        dep.machine = sandbox_info.machine;
                        child_info = sandbox_info;
                        dep.origin = origin_of(in_sandbox, opts,
                                               sandbox_info.machine,
                                               own_origin_dirs);
                        dep.out_of_package_search_path = resolved;
                    }
                }
                dep.version_needs = child_info.version_needs;
                if (opts.hash_bundles && dep.kind == DependencyKind::Bundle) {
                    try {
                        // dep.resolved_path, not `resolved`: the two differ when
                        // a host-only search path was disregarded above, and
                        // hashing the disregarded file would publish a digest of
                        // something no launch will ever load.
                        dep.sha256 =
                            crypto::sha256_file_hex(dep.resolved_path);
                    } catch (const std::exception&) {
                    }
                }
            }

            const std::size_t idx = report.dependencies.size();
            const fs::path walk = dep.resolved_path;
            index.emplace(soname, idx);
            report.dependencies.push_back(std::move(dep));

            // Recurse only into resolvable bundle libraries, and walk the file
            // the SANDBOX will load -- its own DT_NEEDED set is what matters,
            // and a host-only copy can differ from the one in /usr.
            if (opts.recurse && !walk.empty() &&
                report.dependencies[idx].kind == DependencyKind::Bundle) {
                on_path.insert(soname);
                visit(walk, child_info, soname);
                on_path.erase(soname);
            }
        }
    }
};

} // namespace

DependencyReport analyze_dependencies(const fs::path& root,
                                      const DependencyOptions& opts) {
    DependencyReport report;
    report.root = root;
    report.root_info = elf::read(root);
    if (!report.root_info.is_elf) return report;

    Resolver resolver{opts, report, {}, {}};
    resolver.on_path.insert("<root>");
    resolver.visit(root, report.root_info, "<root>");

    // Consult any language-runtime hooks (none registered in this phase).
    for (const std::shared_ptr<LanguageRuntimeHook>& hook : hooks()) {
        const std::vector<Dependency> extra = hook->detect(root, opts);
        for (const Dependency& d : extra) {
            if (resolver.index.find(d.soname) == resolver.index.end()) {
                resolver.index.emplace(d.soname, report.dependencies.size());
                report.dependencies.push_back(d);
            }
        }
    }

    std::sort(report.dependencies.begin(), report.dependencies.end(),
              [](const Dependency& a, const Dependency& b) {
                  return a.soname < b.soname;
              });
    return report;
}

} // namespace lexe
