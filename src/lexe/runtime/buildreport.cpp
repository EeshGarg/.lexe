// buildreport — see buildreport.hpp. Assembly + frontend-neutral rendering.

#include "lexe/runtime/buildreport.hpp"

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
    // Core Portable is the profile that claims cross-distribution portability,
    // so it — and only it — is verified against the Tux32 Core 1 contract. The
    // build host must not silently become the compatibility target.
    if (profile == RuntimeProfile::CorePortable) {
        r.core1 = verify_against_profile(r.dependencies, tux32_core_1());
    }
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
        // WHERE it was found, never left to the reader's inference. This
        // heading used to read "Bundled libraries" over a list that could
        // include libraries found on the build host, with digests, which reads
        // as "the package carries these and they are verified".
        switch (d->origin) {
        case DependencyOrigin::Payload:
            os << "  [in the package]";
            break;
        case DependencyOrigin::System:
            os << "  [found on this host, NOT in the package]";
            break;
        case DependencyOrigin::Elsewhere:
            os << "  [found only at " << d->resolved_path.string()
               << ", which a sandboxed launch will not have]";
            break;
        case DependencyOrigin::None:
            break;
        }
        // The rpath that was found first and then disregarded. Printed because
        // it is usually an absolute build-tree path left in by the link step,
        // and the publisher is the only person who can remove it — they will
        // otherwise be told the library came from the host with no hint that
        // their binary is carrying a dead search path at all.
        if (!d->out_of_package_search_path.empty()) {
            os << "\n        its DT_RPATH/DT_RUNPATH points at "
               << d->out_of_package_search_path.string()
               << ", outside the package — disregarded, as a sandboxed launch "
                  "will not have it";
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
    if (r.profile_declared) {
        os << "Runtime profile: " << pinfo.name << " (" << pinfo.portability
           << " portability)\n";
    } else {
        // FORMAT §5.7: an absent or unknown declaration is NO profile -- never
        // a substituted default, and so nothing to assess against.
        os << "Runtime profile: none declared (not assessed)\n";
    }

    if (r.core1.has_value()) {
        const Core1VerifyResult& c = *r.core1;
        os << "Tux32 " << c.profile_id << ": " << to_string(c.verdict);
        if (!c.required_glibc.empty()) {
            os << " (needs glibc " << c.required_glibc << ", ceiling "
               << c.glibc_ceiling << ")";
        }
        os << "\n                 " << c.detail << "\n";
        for (const Core1Offender& o : c.symbol_offenders) {
            os << "    ! " << o.object << " requires " << o.version << "\n";
        }
    }

    const DependencyReport& d = r.dependencies;
    os << "Dependencies:    " << d.dependencies.size() << " total — "
       << d.count(DependencyKind::HostInterface) << " host, "
       << d.count(DependencyKind::Bundle) << " bundle, "
       << d.count(DependencyKind::Forbidden) << " forbidden, "
       << d.count(DependencyKind::Unresolved) << " unresolved\n";
    // "to bundle", not "bundled": DependencyKind::Bundle is a RECOMMENDATION
    // that the library be carried, not a finding that it already is. Each entry
    // states where it was actually found.
    list_kind(os, d, DependencyKind::Bundle, "Libraries to bundle", true);
    list_kind(os, d, DependencyKind::HostInterface, "Host interfaces", false);
    list_kind(os, d, DependencyKind::Forbidden, "Forbidden (host must provide)", false);
    list_kind(os, d, DependencyKind::Unresolved, "Unresolved", false);

    // "Will it start?", stated separately from "what does it need?", because
    // the same bytes can pass one and fail the other.
    if (r.runtime_contract_checked) {
        if (r.runtime_unreachable.empty()) {
            os << "Runtime contract: satisfied — the dynamic loader can reach "
                  "every dependency\n";
        } else {
            os << "Runtime contract: NOT satisfied — "
               << r.runtime_unreachable.size() << " dependenc"
               << (r.runtime_unreachable.size() == 1 ? "y" : "ies")
               << " the loader cannot reach at launch:\n";
            for (const std::string& soname : r.runtime_unreachable) {
                os << "    ! " << soname << "\n";
            }
            os << "                  The files may well be in the package. The "
                  "loader searches DT_RPATH/DT_RUNPATH and then the system "
                  "directories, so a\n                  bundled library is "
                  "reachable only through an $ORIGIN-relative rpath.\n";
        }
    }

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
    if (r.profile_declared) {
        j["runtimeProfile"] = to_string(r.profile);
    } else {
        j["runtimeProfile"] = nullptr; // §5.7: none declared, none substituted
    }
    j["permissions"] = r.permissions;
    if (!r.signing_fingerprint.empty()) j["signingKey"] = r.signing_fingerprint;

    ordered_json deps = ordered_json::array();
    for (const Dependency& d : r.dependencies.dependencies) {
        // `origin` sits next to `sha256` deliberately. Without it a consumer
        // reads a soname, a digest and the word "bundle" and concludes the
        // package carries a verified copy of that library -- which is false for
        // anything found on the analysing host. The text report states this too;
        // a machine-readable surface that omitted it would just be the same
        // mistake for a different audience.
        deps.push_back({{"soname", d.soname},
                        {"kind", to_string(d.kind)},
                        {"origin", to_string(d.origin)},
                        {"resolvedPath", d.resolved_path.string()},
                        // Empty in the ordinary case. Non-empty means the
                        // binary carries a DT_RPATH/DT_RUNPATH pointing outside
                        // the package that was found first and disregarded --
                        // almost always an absolute build-tree path left in by
                        // the link step, and a publisher's gate wants to see it.
                        {"outOfPackageSearchPath",
                         d.out_of_package_search_path.string()},
                        {"reason", d.reason},
                        {"recommendation", d.recommendation},
                        {"sha256", d.sha256},
                        {"neededBy", d.needed_by}});
    }
    j["dependencies"] = std::move(deps);
    // A gate needs this to be unambiguous, including the "not asked" case: a
    // missing key and an empty list must not read the same.
    if (r.runtime_contract_checked) {
        j["runtimeContract"] = {
            {"satisfied", r.runtime_unreachable.empty()},
            {"unreachable", r.runtime_unreachable}};
    }
    // `unresolved` answers the ADVISORY question — "is there anywhere this could
    // come from" — and a gate that reads only it will pass a package that cannot
    // start, because a library sitting in payload/lib with no rpath pointing at
    // it resolves here and is unreachable to the loader. `runtimeUnreachable` is
    // the launch question. Both are published because both are real, and a
    // consumer that cares whether the thing will RUN wants the second.
    //
    // `bundle` is likewise a RECOMMENDATION count — how many dependencies the
    // engine says to carry — and it read the same, 1, for a package whose only
    // payload file was its executable and for the control that genuinely
    // carried payload/lib/libz.so.1. `origin` distinguishes them per
    // dependency; nothing aggregated it, so a gate reading only the summary
    // could not tell "ships zlib" from "was told to ship zlib".
    //
    // `bundle` keeps its published meaning and `bundledInPackage` is added
    // beside it. docs/COMPATIBILITY.md rates `--json` shapes Informative --
    // "may gain fields; treat additively" -- which is permission to add a key
    // and not to silently change what an existing one counts under readers who
    // cannot see the change.
    std::size_t bundled_in_package = 0;
    for (const Dependency* d : r.dependencies.of_kind(DependencyKind::Bundle)) {
        if (d->origin == DependencyOrigin::Payload) ++bundled_in_package;
    }
    j["dependencySummary"] = {
        {"total", r.dependencies.dependencies.size()},
        {"hostInterface", r.dependencies.count(DependencyKind::HostInterface)},
        {"bundle", r.dependencies.count(DependencyKind::Bundle)},
        {"bundledInPackage", bundled_in_package},
        {"forbidden", r.dependencies.count(DependencyKind::Forbidden)},
        {"unresolved", r.dependencies.count(DependencyKind::Unresolved)},
    };
    if (r.runtime_contract_checked) {
        j["dependencySummary"]["runtimeUnreachable"] =
            r.runtime_unreachable.size();
    }
    j["glibcRequirement"] = r.dependencies.max_glibc_version();
    if (!r.dependencies.cycles.empty()) j["cycles"] = r.dependencies.cycles;

    if (r.profile_declared) j["profileAssessment"] = {
        {"claimsPortability", r.profile_assessment.claims_portability},
        {"warnings", r.profile_assessment.warnings},
        {"notes", r.profile_assessment.notes}};

    if (r.core1.has_value()) {
        const Core1VerifyResult& c = *r.core1;
        ordered_json offenders = ordered_json::array();
        for (const Core1Offender& o : c.symbol_offenders) {
            offenders.push_back({{"object", o.object}, {"version", o.version}});
        }
        j["tux32"] = {
            {"profile", c.profile_id},
            {"verdict", to_string(c.verdict)},
            {"conformant", c.conformant()},
            {"glibcCeiling", c.glibc_ceiling},
            {"requiredGlibc", c.required_glibc},
            {"symbolOffenders", std::move(offenders)},
            {"forbidden", c.forbidden},
            {"unresolved", c.unresolved},
            {"detail", c.detail},
        };
    }

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
