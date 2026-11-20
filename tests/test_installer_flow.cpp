// The double-click installer's decision layer (src/gui/installer_flow.hpp)
// (The console's friendly-time helpers are in test_ui.cpp, beside ui.cpp's
// other pure helpers.)
//
// GTK-free: LEXE_GUI_VIEWMODEL_ONLY drops every GTK symbol from ui.cpp, so
// these run on every platform. What is pinned here is what the window SAYS
// and OFFERS — in particular that installing and opening are never confused,
// that every consent is separate, and that nothing from a package that failed
// verification is presented as fact.

#define LEXE_GUI_VIEWMODEL_ONLY 1
#include "gui/installer_flow.hpp"

#include <doctest/doctest.h>

#include "helpers.hpp"

#include <optional>
#include <string>

namespace {

using lexe::Manifest;
using lexe::gui::InstallerPlan;
using lexe::gui::InstallIntent;
using lexe::gui::ViewModel;

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

Manifest manifest(const std::string& version = "2.0.0",
                  const std::string& permissions = "[]",
                  const std::string& extra = "") {
    return Manifest::parse(R"({
      "lexeVersion": "0.1",
      "id": "com.example.notes",
      "name": "Notes",
      "version": ")" + version + R"(",
      "publisher": { "name": "Example Software",
                     "publicKey": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
      "applicationType": "native",
      "architectures": ["x86_64"],
      "entrypoint": { "executable": "bin/notes" },
      "install": { "scope": "user", "mode": "bundled" },
      "permissions": )" + permissions + extra + R"(
    })");
}

lexe::VerificationReport green() {
    lexe::VerificationReport r;
    r.stages.push_back({"structure", true, "ok", {}});
    return r;
}

lexe::VerificationReport failed_at(const std::string& stage) {
    lexe::VerificationReport r;
    r.stages.push_back({"structure", true, "ok", {}});
    r.stages.push_back({stage, false, "the reader's exact words", {}});
    return r;
}

ViewModel installable(const Manifest& m) {
    ViewModel vm;
    vm.app_name = m.name;
    vm.app_id = m.id;
    vm.verified = true;
    vm.can_install = true;
    vm.status_text = "Signed — publisher not verified (first seen)";
    vm.trust_severity = "caution";
    return vm;
}

lexe::IsolationCapabilities sandbox() {
    lexe::IsolationCapabilities c;
    c.status = lexe::CapabilityStatus::Available;
    c.backend_present = c.user_namespaces = c.network_namespaces =
        c.bind_mounts = true;
    return c;
}

} // namespace

TEST_SUITE("installer_flow") {

TEST_CASE("not installed: Install, and the primary action installs") {
    lexe::test::TempLexeHome home;
    const Manifest m = manifest();
    const InstallerPlan plan =
        lexe::gui::plan_installer(installable(m), green(), m, "", sandbox());
    CHECK(plan.intent == InstallIntent::Install);
    CHECK(plan.primary_label == "Install");
    CHECK_FALSE(plan.primary_is_open);
    CHECK(plan.secondary_label.empty());
    CHECK(plan.headline == "Install Notes?");
    CHECK(has(plan.subline, "Example Software"));
    CHECK(has(plan.subline, "2.0.0"));
    CHECK(lexe::gui::primary_enabled(plan, false, false, false));
    CHECK(has(plan.done_headline, "is installed"));
}

TEST_CASE("the same version installed: the primary action OPENS, it never reinstalls") {
    // Executing and installing are different acts. Opening an installed app's
    // package used to offer "Install" again.
    lexe::test::TempLexeHome home;
    const Manifest m = manifest("2.0.0");
    const InstallerPlan plan =
        lexe::gui::plan_installer(installable(m), green(), m, "2.0.0", sandbox());
    CHECK(plan.intent == InstallIntent::Reinstall);
    CHECK(plan.primary_label == "Open");
    CHECK(plan.primary_is_open);
    CHECK(plan.secondary_label == "Reinstall");
    CHECK(has(plan.headline, "already installed"));
    CHECK(lexe::gui::primary_enabled(plan, false, false, false));
    CHECK(lexe::gui::secondary_enabled(plan, false, false));
}

TEST_CASE("an older version installed: Update, saying from what to what") {
    lexe::test::TempLexeHome home;
    const Manifest m = manifest("2.0.0");
    const InstallerPlan plan =
        lexe::gui::plan_installer(installable(m), green(), m, "1.0.0", sandbox());
    CHECK(plan.intent == InstallIntent::Update);
    CHECK(plan.primary_label == "Update");
    CHECK(has(plan.context_line, "1.0.0"));
    CHECK(has(plan.context_line, "2.0.0"));
    CHECK_FALSE(plan.needs_downgrade_consent);
}

TEST_CASE("a newer version installed: Downgrade waits on its own consent") {
    // The GUI used to pass no allow_downgrade, so this failed at the very end
    // with an error the user had never been asked about.
    lexe::test::TempLexeHome home;
    const Manifest m = manifest("1.0.0");
    const InstallerPlan plan =
        lexe::gui::plan_installer(installable(m), green(), m, "2.0.0", sandbox());
    CHECK(plan.intent == InstallIntent::Downgrade);
    CHECK(plan.primary_destructive);
    CHECK(plan.needs_downgrade_consent);
    CHECK(has(plan.downgrade_consent_label, "2.0.0"));
    CHECK_FALSE(lexe::gui::primary_enabled(plan, false, false, false));
    CHECK(lexe::gui::primary_enabled(plan, true, false, false));
}

TEST_CASE("an update asking for NEW permissions names them and waits on that consent alone") {
    lexe::test::TempLexeHome home;
    const Manifest m = manifest("2.0.0", R"(["network"])");
    ViewModel vm = installable(m);
    vm.permission_expansion = true;
    lexe::PermissionDelta delta;
    delta.added = {"network"};
    const InstallerPlan plan =
        lexe::gui::plan_installer(vm, green(), m, "1.0.0", sandbox(), delta);
    CHECK(plan.needs_permission_consent);
    CHECK(has(plan.permission_consent_label, "Network access"));
    CHECK_FALSE(lexe::gui::primary_enabled(plan, false, false, false));
    // The downgrade box is not the permission box.
    CHECK_FALSE(lexe::gui::primary_enabled(plan, true, false, false));
    CHECK(lexe::gui::primary_enabled(plan, false, true, false));
    // And the ability itself is marked as new in the plain-language list.
    bool marked = false;
    for (const auto& line : plan.capabilities) {
        if (has(line.text, "internet") && has(line.text, "new in this version")) {
            marked = true;
        }
    }
    CHECK(marked);
}

TEST_CASE("a fresh install needs no permission consent: the review IS the consent") {
    lexe::test::TempLexeHome home;
    const Manifest m = manifest("2.0.0", R"(["network"])");
    ViewModel vm = installable(m);
    vm.permission_expansion = true; // no prior approval exists at all
    const InstallerPlan plan =
        lexe::gui::plan_installer(vm, green(), m, "", sandbox());
    CHECK_FALSE(plan.needs_permission_consent);
}

TEST_CASE("a portable package waits on compile approval, and is blocked when it cannot build") {
    lexe::test::TempLexeHome home;
    const Manifest m = manifest();
    ViewModel vm = installable(m);
    vm.requires_compile_approval = true;
    vm.compile_possible = true;
    vm.compile_consent_label = "Compile it here";
    InstallerPlan plan = lexe::gui::plan_installer(vm, green(), m, "", sandbox());
    CHECK(plan.needs_compile_consent);
    CHECK_FALSE(lexe::gui::primary_enabled(plan, false, false, false));
    CHECK(lexe::gui::primary_enabled(plan, false, false, true));

    vm.compile_possible = false;
    vm.compile_text = "missing: cc";
    plan = lexe::gui::plan_installer(vm, green(), m, "", sandbox());
    CHECK_FALSE(plan.blocked_reason.empty());
    CHECK_FALSE(lexe::gui::primary_enabled(plan, false, false, true));
}

TEST_CASE("a package that failed verification describes nothing as fact") {
    lexe::test::TempLexeHome home;
    const Manifest m = manifest();
    ViewModel vm = installable(m);
    vm.verified = false;
    vm.can_install = false;
    const InstallerPlan plan =
        lexe::gui::plan_installer(vm, failed_at("hashes"), m, "", sandbox());
    CHECK(plan.intent == InstallIntent::Refused);
    CHECK(plan.capabilities.empty());          // no "runs in a sandbox" for a forgery
    CHECK_FALSE(has(plan.headline, "Notes"));   // its name is not our heading
    CHECK(has(plan.subline, "claims"));
    CHECK(has(plan.subline, "unverified"));
    CHECK(has(plan.blocked_reason, "changed after it was signed"));
    CHECK(plan.trust_severity == "danger");
    CHECK_FALSE(lexe::gui::primary_enabled(plan, true, true, true));
}

TEST_CASE("each verification stage gets a sentence a person can act on") {
    for (const char* stage : {"structure", "manifest", "key", "manifest-signature",
                              "payload-signature", "hashes", "compatibility",
                              "payload-role"}) {
        CAPTURE(stage);
        const std::string text = lexe::gui::refusal_summary(failed_at(stage));
        CHECK_FALSE(text.empty());
        CHECK(text != "It did not pass verification.");
        CHECK_FALSE(has(text, stage)); // no stage jargon in the sentence itself
    }
}

TEST_CASE("verified but refused by local trust: the trust remedy, not a stage") {
    lexe::test::TempLexeHome home;
    const Manifest m = manifest();
    ViewModel vm = installable(m);
    vm.can_install = false;
    vm.trust_severity = "danger";
    vm.trust_remedy = "The signing key changed since you installed it.";
    const InstallerPlan plan = lexe::gui::plan_installer(vm, green(), m, "1.0.0",
                                                         sandbox());
    CHECK(plan.intent == InstallIntent::Refused);
    CHECK(plan.blocked_reason == vm.trust_remedy);
    CHECK(plan.capabilities.empty());
}

TEST_CASE("capability lines are claims the runtime backs") {
    lexe::test::TempLexeHome home;
    const Manifest offline = manifest();
    auto lines = lexe::gui::capability_lines(offline, sandbox());
    REQUIRE_FALSE(lines.empty());
    CHECK(lines.front().tone == "ok");
    CHECK(has(lines.front().text, "sandbox"));
    bool no_net = false;
    for (const auto& l : lines) no_net |= has(l.text, "Cannot connect");
    CHECK(no_net);

    // Without a working sandbox it says so, and does not promise "no internet".
    lexe::IsolationCapabilities none;
    lines = lexe::gui::capability_lines(offline, none);
    CHECK(lines.front().tone == "danger");
    for (const auto& l : lines) CHECK_FALSE(has(l.text, "Cannot connect"));

    // An advisory permission says it is advisory.
    const Manifest files = manifest("2.0.0", R"(["user-files-selected"])");
    bool advisory = false;
    for (const auto& l : lexe::gui::capability_lines(files, sandbox())) {
        advisory |= has(l.text, "not enforced");
    }
    CHECK(advisory);

    // An update source is named by host.
    const Manifest updates = manifest(
        "2.0.0", "[]",
        R"(, "updates": {"enabled": true, "manifest": "https://u.example.org/n.json"})");
    bool host = false;
    for (const auto& l : lexe::gui::capability_lines(updates, sandbox())) {
        host |= has(l.text, "u.example.org");
    }
    CHECK(host);
}

TEST_CASE("the best icon is a large raster, then the vector") {
    CHECK(lexe::gui::best_icon_entry({"icons/64.png", "icons/128.png",
                                      "icons/scalable.svg"}) == "icons/128.png");
    CHECK(lexe::gui::best_icon_entry({"icons/64.png", "icons/scalable.svg"}) ==
          "icons/scalable.svg");
    CHECK(lexe::gui::best_icon_entry({"payload/x", "lexe.json"}).empty());
}

} // TEST_SUITE("installer_flow")
