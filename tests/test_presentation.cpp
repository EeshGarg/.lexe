// Frontend-neutral presentation model tests (runtime-trust WS10). The CLI and
// GTK render these same values, so pinning them here pins both frontends.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/isolation.hpp"
#include "core/permissions.hpp"
#include "core/presentation.hpp"
#include "core/trust.hpp"

#include <string>

using namespace lexe;
using namespace lexe::presentation;

namespace {

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

TrustEvaluation make_eval(PublisherKeyState key_state, TrustDecision decision,
                          SignatureState sig = SignatureState::Valid) {
    TrustEvaluation e;
    e.app_id = "com.example.app";
    e.signature = sig;
    e.key_state = key_state;
    e.decision = decision;
    e.presented = key_fingerprint(test::make_keypair().public_key);
    return e;
}

IsolationCapabilities linux_available() {
    IsolationCapabilities c;
    c.status = CapabilityStatus::Available;
    c.backend_present = true;
    c.user_namespaces = true;
    c.network_namespaces = true;
    c.bind_mounts = true;
    return c;
}

} // namespace

TEST_SUITE("presentation") {

TEST_CASE("authenticity: first-seen is caution, never styled as verified") {
    const AuthenticityView v = present_authenticity(
        make_eval(PublisherKeyState::FirstSeen, TrustDecision::AllowFirstInstall),
        "Example Corp");
    CHECK(v.severity == AuthenticityView::Severity::Caution); // NOT Ok/green
    CHECK(v.can_proceed);
    CHECK(has(v.headline, "first seen"));
    CHECK(has(v.headline, "not verified"));
    CHECK(has(v.identity_caveat, "not the publisher's real-world identity"));
    CHECK(v.fingerprint_full.size() == 64);
    CHECK(has(v.signature_text, "valid"));
    CHECK(std::string(to_string(v.severity)) == "caution");
}

TEST_CASE("authenticity: known and explicitly-trusted keys are ok") {
    const AuthenticityView known = present_authenticity(
        make_eval(PublisherKeyState::KnownMatching, TrustDecision::AllowKnownUpdate),
        "Example Corp");
    CHECK(known.severity == AuthenticityView::Severity::Ok);
    CHECK(known.can_proceed);
    CHECK(has(known.key_text, "matches the key"));

    const AuthenticityView trusted = present_authenticity(
        make_eval(PublisherKeyState::ExplicitlyTrusted, TrustDecision::AllowKnownUpdate),
        "Example Corp");
    CHECK(trusted.severity == AuthenticityView::Severity::Ok);
    CHECK(has(trusted.key_text, "local decision"));
}

TEST_CASE("authenticity: changed / blocked / corrupt / conflict are danger and cannot proceed") {
    for (const auto& c :
         {std::make_pair(PublisherKeyState::Changed, TrustDecision::RejectChangedKey),
          std::make_pair(PublisherKeyState::Blocked, TrustDecision::RejectBlocked),
          std::make_pair(PublisherKeyState::TrustUnavailable, TrustDecision::RejectCorruptTrust),
          std::make_pair(PublisherKeyState::RetainedDataConflict,
                         TrustDecision::RejectRetainedDataConflict)}) {
        const AuthenticityView v =
            present_authenticity(make_eval(c.first, c.second), "Example Corp");
        CHECK(v.severity == AuthenticityView::Severity::Danger);
        CHECK_FALSE(v.can_proceed);
        CHECK(has(v.headline, "Refused"));
    }
}

TEST_CASE("authenticity: an invalid signature is danger even for a known key") {
    const AuthenticityView v = present_authenticity(
        make_eval(PublisherKeyState::KnownMatching, TrustDecision::RejectInvalidSignature,
                  SignatureState::Invalid),
        "Example Corp");
    CHECK(v.severity == AuthenticityView::Severity::Danger);
    CHECK_FALSE(v.can_proceed);
    CHECK(has(v.headline, "signature is not valid"));
}

TEST_CASE("permissions: truthful labels and enforcement per platform") {
    CHECK(describe_permission("network") == "Network access");
    CHECK(describe_permission("user-files-selected") == "Access to files you select");
    CHECK(describe_permission("com.unknown.thing") == "com.unknown.thing");

    const IsolationCapabilities avail = linux_available();
    CHECK(has(permission_enforcement("network", avail), "enforced"));
    CHECK(has(permission_enforcement("user-files-selected", avail), "advisory"));

    IsolationCapabilities win;
    win.status = CapabilityStatus::PolicyUnsupported;
    CHECK(permission_enforcement("network", win) == "not enforced on this platform");

    IsolationCapabilities nonet = linux_available();
    nonet.network_namespaces = false;
    CHECK(has(permission_enforcement("network", nonet), "unavailable"));

    const std::vector<PermissionView> rows =
        present_permissions({"network", "user-files-selected"}, avail);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].id == "network");
    CHECK(rows[0].title == "Network access");
}

TEST_CASE("permission delta keeps added/removed/unchanged separate") {
    const NormalizedPermissions approved = normalized_from_ids({});
    const NormalizedPermissions candidate = normalized_from_ids({"network"});
    const PermissionDeltaView v =
        present_permission_delta(permission_delta(approved, candidate));
    CHECK(v.expands);
    REQUIRE(v.added.size() == 1);
    CHECK(v.added[0] == "Network access");
    CHECK(v.removed.empty());
}

TEST_CASE("isolation: truthful summary per capability status") {
    const IsolationView avail = present_isolation(linux_available());
    CHECK(has(avail.headline, "enforced"));
    CHECK(has(avail.platform_caveat, "seccomp"));
    CHECK(has(avail.platform_caveat, "GUI forwarding is unavailable"));
    // The control rows spell out advisory / unavailable / not-implemented truths.
    bool saw_advisory = false, saw_gui_unavailable = false, saw_seccomp = false;
    for (const auto& row : avail.controls) {
        if (has(row.first, "File selection") && row.second == "advisory") saw_advisory = true;
        if (has(row.first, "GUI forwarding") && row.second == "unavailable") saw_gui_unavailable = true;
        if (has(row.first, "seccomp") && row.second == "not implemented") saw_seccomp = true;
    }
    CHECK(saw_advisory);
    CHECK(saw_gui_unavailable);
    CHECK(saw_seccomp);

    IsolationCapabilities win;
    win.status = CapabilityStatus::PolicyUnsupported;
    const IsolationView w = present_isolation(win);
    CHECK(has(w.headline, "No OS-level isolation"));
    CHECK(has(w.platform_caveat, "no runtime containment"));

    IsolationCapabilities unavail;
    unavail.status = CapabilityStatus::Unavailable;
    CHECK(has(present_isolation(unavail).headline, "launch will be refused"));
}

} // TEST_SUITE("presentation")
