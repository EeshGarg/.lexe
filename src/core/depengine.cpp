// depengine — see depengine.hpp. Direct-ELF dependency resolution + typed
// classification. Resolution is deterministic and read-only.

#include "core/depengine.hpp"

#include "core/crypto.hpp"

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
    for (const std::string& v : all_version_needs()) {
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
    if (best_major < 0) return "";
    return std::to_string(best_major) + "." + std::to_string(best_minor);
}

namespace {

/// Resolve a soname to a file under an ordered set of directories.
fs::path resolve(const std::string& soname, const std::vector<fs::path>& dirs) {
    std::error_code ec;
    for (const fs::path& dir : dirs) {
        const fs::path candidate = dir / soname;
        if (fs::is_regular_file(candidate, ec)) {
            return candidate;
        }
    }
    return {};
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
    std::vector<fs::path> search_dirs(const elf::ElfInfo& info,
                                      const fs::path& object_dir) {
        std::vector<fs::path> dirs = opts.payload_search_paths;
        for (const std::string& e : info.runpath) {
            dirs.push_back(expand_origin(e, object_dir));
        }
        for (const std::string& e : info.rpath) {
            dirs.push_back(expand_origin(e, object_dir));
        }
        for (const fs::path& p : opts.extra_search_paths) dirs.push_back(p);
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
                dep.version_needs = child_info.version_needs;
                if (opts.hash_bundles && dep.kind == DependencyKind::Bundle) {
                    try {
                        dep.sha256 = crypto::sha256_file_hex(resolved);
                    } catch (const std::exception&) {
                    }
                }
            }

            const std::size_t idx = report.dependencies.size();
            index.emplace(soname, idx);
            report.dependencies.push_back(std::move(dep));

            // Recurse only into resolvable bundle libraries.
            if (opts.recurse && !resolved.empty() &&
                report.dependencies[idx].kind == DependencyKind::Bundle) {
                on_path.insert(soname);
                visit(resolved, child_info, soname);
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
