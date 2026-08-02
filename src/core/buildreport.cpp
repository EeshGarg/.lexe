// buildreport — see buildreport.hpp. Assembly + frontend-neutral rendering.

#include "core/buildreport.hpp"

#include <sstream>

namespace lexe {

BuildReport assemble_report(DependencyReport deps, RuntimeProfile profile) {
    BuildReport r;
    r.profile = profile;
    if (!deps.root_info.arch().empty()) {
        r.architectures.push_back(deps.root_info.arch());
    }
    r.profile_assessment = assess_profile(profile, deps);
    r.compatibility = analyze_compatibility(deps);
    r.dependencies = std::move(deps);
    return r;
}

namespace {

const char* compat_marker(CompatLevel l) {
    switch (l) {
    case CompatLevel::Compatible:   return "[ ok ]";
    case CompatLevel::Warning:      return "[warn]";
    case CompatLevel::Incompatible: return "[ no ]";
    }
    return "[warn]";
}

void list_kind(std::ostringstream& os, const DependencyReport& deps,
               DependencyKind kind, const char* heading, bool show_hash) {
    const std::vector<const Dependency*> items = deps.of_kind(kind);
    if (items.empty()) return;
    os << "  " << heading << " (" << items.size() << "):\n";
    for (const Dependency* d : items) {
        os << "    - " << d->soname;
        if (show_hash && !d->sha256.empty()) {
            os << "  sha256:" << d->sha256.substr(0, 12) << "…";
        }
        os << "\n";
    }
}

} // namespace

std::string render_build_report_text(const BuildReport& r) {
    std::ostringstream os;
    const RuntimeProfileInfo& pinfo = runtime_profile_info(r.profile);

    if (!r.app_name.empty()) {
        os << "Application:     " << r.app_name;
        if (!r.app_version.empty()) os << " " << r.app_version;
        if (!r.app_id.empty()) os << " (" << r.app_id << ")";
        os << "\n";
    }
    if (!r.architectures.empty()) {
        os << "Architecture:    ";
        for (std::size_t i = 0; i < r.architectures.size(); ++i) {
            os << (i ? ", " : "") << r.architectures[i];
        }
        os << "\n";
    }
    os << "Runtime profile: " << pinfo.name << " (" << pinfo.portability
       << " portability)\n";

    const DependencyReport& d = r.dependencies;
    os << "Dependencies:    " << d.dependencies.size() << " total — "
       << d.count(DependencyKind::HostInterface) << " host, "
       << d.count(DependencyKind::Bundle) << " bundle, "
       << d.count(DependencyKind::Forbidden) << " forbidden, "
       << d.count(DependencyKind::Unresolved) << " unresolved\n";
    list_kind(os, d, DependencyKind::Bundle, "Bundled libraries", true);
    list_kind(os, d, DependencyKind::HostInterface, "Host interfaces", false);
    list_kind(os, d, DependencyKind::Forbidden, "Forbidden (host must provide)", false);
    list_kind(os, d, DependencyKind::Unresolved, "Unresolved", false);

    if (!r.permissions.empty()) {
        os << "Permissions:     ";
        for (std::size_t i = 0; i < r.permissions.size(); ++i) {
            os << (i ? ", " : "") << r.permissions[i];
        }
        os << "\n";
    }
    if (!r.signing_fingerprint.empty()) {
        os << "Signing key:     " << r.signing_fingerprint << "\n";
    }

    os << "Compatibility:\n";
    for (const TargetCompat& t : r.compatibility.targets) {
        os << "  " << compat_marker(t.level) << " " << t.target.name << " — "
           << t.detail << "\n";
    }
    if (!r.compatibility.warnings.empty()) {
        os << "  Warnings:\n";
        for (const CompatWarning& w : r.compatibility.warnings) {
            os << "    ! " << w.title << ": " << w.explanation << "\n";
        }
    }

    if (!r.output_package.empty()) {
        os << "Output:          " << r.output_package.string();
        if (r.output_size > 0) os << " (" << r.output_size << " bytes)";
        os << "\n";
        if (!r.output_sha256.empty()) {
            os << "Checksum:        sha256:" << r.output_sha256 << "\n";
        }
    }
    return os.str();
}

nlohmann::ordered_json build_report_json(const BuildReport& r) {
    using nlohmann::ordered_json;
    ordered_json j;
    if (!r.app_name.empty() || !r.app_id.empty()) {
        j["application"] = {{"name", r.app_name},
                            {"id", r.app_id},
                            {"version", r.app_version}};
    }
    j["architectures"] = r.architectures;
    j["runtimeProfile"] = to_string(r.profile);
    j["permissions"] = r.permissions;
    if (!r.signing_fingerprint.empty()) j["signingKey"] = r.signing_fingerprint;

    ordered_json deps = ordered_json::array();
    for (const Dependency& d : r.dependencies.dependencies) {
        deps.push_back({{"soname", d.soname},
                        {"kind", to_string(d.kind)},
                        {"resolvedPath", d.resolved_path.string()},
                        {"reason", d.reason},
                        {"recommendation", d.recommendation},
                        {"sha256", d.sha256},
                        {"neededBy", d.needed_by}});
    }
    j["dependencies"] = std::move(deps);
    j["dependencySummary"] = {
        {"total", r.dependencies.dependencies.size()},
        {"hostInterface", r.dependencies.count(DependencyKind::HostInterface)},
        {"bundle", r.dependencies.count(DependencyKind::Bundle)},
        {"forbidden", r.dependencies.count(DependencyKind::Forbidden)},
        {"unresolved", r.dependencies.count(DependencyKind::Unresolved)},
    };
    j["glibcRequirement"] = r.dependencies.max_glibc_version();
    if (!r.dependencies.cycles.empty()) j["cycles"] = r.dependencies.cycles;

    j["profileAssessment"] = {
        {"claimsPortability", r.profile_assessment.claims_portability},
        {"warnings", r.profile_assessment.warnings},
        {"notes", r.profile_assessment.notes}};

    ordered_json targets = ordered_json::array();
    for (const TargetCompat& t : r.compatibility.targets) {
        targets.push_back({{"id", t.target.id},
                           {"name", t.target.name},
                           {"level", to_string(t.level)},
                           {"detail", t.detail}});
    }
    ordered_json warns = ordered_json::array();
    for (const CompatWarning& w : r.compatibility.warnings) {
        warns.push_back({{"title", w.title}, {"explanation", w.explanation}});
    }
    j["compatibility"] = {{"targets", std::move(targets)},
                          {"warnings", std::move(warns)},
                          {"allCompatible", r.compatibility.all_compatible()}};

    if (!r.output_package.empty()) {
        j["output"] = {{"package", r.output_package.string()},
                       {"size", r.output_size},
                       {"sha256", r.output_sha256}};
    }
    return j;
}

} // namespace lexe
