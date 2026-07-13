// manifest module tests (ARCHITECTURE.md #Tests: accept/reject tables,
// round-trip, SPEC.md's own example manifest). Every test case constructs
// lexe::test::TempLexeHome first so LEXE_HOME never touches the real profile.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/manifest.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

using lexe::Error;
using lexe::Manifest;
using lexe::VerificationError;
using nlohmann::json;

namespace {

/// A fully valid FORMAT-0.1 §5 manifest that the mutation tables start from.
json base_manifest() {
    return json{
        {"lexeVersion", "0.1"},
        {"id", "com.example.application"},
        {"name", "Example Application"},
        {"version", "1.4.2"},
        {"publisher",
         {{"name", "Example Corporation"},
          {"website", "https://example.com"},
          {"publicKey",
           "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}},
        {"applicationType", "native"},
        {"architectures", json::array({"x86_64", "aarch64"})},
        {"entrypoint",
         {{"executable", "bin/example"}, {"arguments", json::array()}}},
        {"install",
         {{"scope", "user"}, {"mode", "bundled"}, {"estimatedSize", 125829120}}},
        {"permissions", json::array({"network", "user-files-selected"})},
        {"updates",
         {{"enabled", true},
          {"channel", "stable"},
          {"manifest", "https://example.com/releases/update.json"},
          {"allowSourceChange", true}}},
        {"integration",
         {{"desktopEntry", true},
          {"categories", json::array({"Utility"})},
          {"fileAssociations",
           json::array({{{"extension", ".example"},
                         {"mimeType", "application/x-example"}}})}}},
    };
}

Manifest parse_json(const json& j) { return Manifest::parse(j.dump()); }

/// One row of a mutation-driven accept/reject table.
struct Row {
    const char* description;
    std::function<void(json&)> mutate;
};

void check_rejects(const std::vector<Row>& rows) {
    for (const Row& row : rows) {
        CAPTURE(row.description);
        json j = base_manifest();
        row.mutate(j);
        CHECK_THROWS_AS(parse_json(j), VerificationError);
    }
}

void check_accepts(const std::vector<Row>& rows) {
    for (const Row& row : rows) {
        CAPTURE(row.description);
        json j = base_manifest();
        row.mutate(j);
        CHECK_NOTHROW(parse_json(j));
    }
}

bool same_manifest(const Manifest& a, const Manifest& b) {
    bool ok = true;
    auto eq = [&](const auto& x, const auto& y, const char* field) {
        if (!(x == y)) {
            ok = false;
            MESSAGE("manifest field mismatch: " << field);
        }
    };
    eq(a.lexe_version, b.lexe_version, "lexe_version");
    eq(a.id, b.id, "id");
    eq(a.name, b.name, "name");
    eq(a.version, b.version, "version");
    eq(a.publisher_name, b.publisher_name, "publisher_name");
    eq(a.publisher_public_key, b.publisher_public_key, "publisher_public_key");
    eq(a.publisher_website, b.publisher_website, "publisher_website");
    eq(a.application_type, b.application_type, "application_type");
    eq(a.architectures, b.architectures, "architectures");
    eq(a.entrypoint_executable, b.entrypoint_executable,
       "entrypoint_executable");
    eq(a.entrypoint_arguments, b.entrypoint_arguments, "entrypoint_arguments");
    eq(a.install_scope, b.install_scope, "install_scope");
    eq(a.install_mode, b.install_mode, "install_mode");
    eq(a.install_estimated_size, b.install_estimated_size,
       "install_estimated_size");
    eq(a.permissions, b.permissions, "permissions");
    eq(a.updates_enabled, b.updates_enabled, "updates_enabled");
    eq(a.updates_channel, b.updates_channel, "updates_channel");
    eq(a.updates_manifest_url, b.updates_manifest_url, "updates_manifest_url");
    eq(a.updates_allow_source_change, b.updates_allow_source_change,
       "updates_allow_source_change");
    eq(a.integration_desktop_entry, b.integration_desktop_entry,
       "integration_desktop_entry");
    eq(a.categories, b.categories, "categories");
    eq(a.file_associations.size(), b.file_associations.size(),
       "file_associations.size");
    if (a.file_associations.size() == b.file_associations.size()) {
        for (std::size_t i = 0; i < a.file_associations.size(); ++i) {
            eq(a.file_associations[i].extension,
               b.file_associations[i].extension, "file_associations.extension");
            eq(a.file_associations[i].mime_type,
               b.file_associations[i].mime_type, "file_associations.mime_type");
        }
    }
    return ok;
}

/// The example manifest copied verbatim from SPEC.md #Application-Manifest.
const char* kSpecExample = R"JSON({
  "lexeVersion": "0.1",
  "id": "com.example.application",
  "name": "Example Application",
  "version": "1.4.2",
  "publisher": {
    "name": "Example Corporation",
    "website": "https://example.com",
    "publicKey": "ed25519:..."
  },
  "applicationType": "native",
  "architectures": [
    "x86_64",
    "aarch64"
  ],
  "entrypoint": {
    "executable": "bin/example",
    "arguments": []
  },
  "install": {
    "scope": "user",
    "mode": "bundled",
    "estimatedSize": 125829120
  },
  "permissions": [
    "network",
    "user-files-selected"
  ],
  "updates": {
    "enabled": true,
    "channel": "stable",
    "manifest": "https://example.com/releases/update.json",
    "allowSourceChange": true
  },
  "integration": {
    "desktopEntry": true,
    "categories": [
      "Utility"
    ],
    "fileAssociations": [
      {
        "extension": ".example",
        "mimeType": "application/x-example"
      }
    ]
  }
})JSON";

} // namespace

TEST_SUITE("manifest") {

TEST_CASE("SPEC.md example manifest parses with every field faithful") {
    lexe::test::TempLexeHome home;
    const Manifest m = Manifest::parse(kSpecExample);

    CHECK(m.lexe_version == "0.1");
    CHECK(m.id == "com.example.application");
    CHECK(m.name == "Example Application");
    CHECK(m.version == "1.4.2");
    CHECK(m.publisher_name == "Example Corporation");
    CHECK(m.publisher_website == "https://example.com");
    CHECK(m.publisher_public_key == "ed25519:...");
    CHECK(m.application_type == "native");
    CHECK(m.architectures ==
          std::vector<std::string>{"x86_64", "aarch64"});
    CHECK(m.entrypoint_executable == "bin/example");
    CHECK(m.entrypoint_arguments.empty());
    CHECK(m.install_scope == "user");
    CHECK(m.install_mode == "bundled");
    CHECK(m.install_estimated_size == 125829120u);
    CHECK(m.permissions ==
          std::vector<std::string>{"network", "user-files-selected"});
    CHECK(m.updates_enabled == true);
    CHECK(m.updates_channel == "stable");
    CHECK(m.updates_manifest_url == "https://example.com/releases/update.json");
    CHECK(m.updates_allow_source_change == true);
    CHECK(m.integration_desktop_entry == true);
    CHECK(m.categories == std::vector<std::string>{"Utility"});
    REQUIRE(m.file_associations.size() == 1);
    CHECK(m.file_associations[0].extension == ".example");
    CHECK(m.file_associations[0].mime_type == "application/x-example");
}

TEST_CASE("minimal manifest parses and applies every documented default") {
    lexe::test::TempLexeHome home;
    const json minimal = {
        {"lexeVersion", "0.1"},
        {"id", "org.example.app"},
        {"name", "App"},
        {"version", "1"},
        {"publisher",
         {{"name", "P"},
          {"publicKey",
           "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}},
        {"applicationType", "native"},
        {"architectures", json::array({"x86_64"})},
        {"entrypoint", {{"executable", "app"}}},
        {"install", {{"mode", "bundled"}}},
    };
    const Manifest m = parse_json(minimal);

    CHECK(m.entrypoint_arguments.empty());       // default []
    CHECK(m.publisher_website.empty());          // default ""
    CHECK(m.install_scope == "user");            // default "user"
    CHECK(m.install_estimated_size == 0u);       // 0 = not provided
    CHECK(m.permissions.empty());                // default []
    CHECK(m.updates_enabled == false);           // disabled when absent
    CHECK(m.updates_channel == "stable");
    CHECK(m.updates_manifest_url.empty());
    CHECK(m.updates_allow_source_change == true);
    CHECK(m.integration_desktop_entry == true);
    CHECK(m.categories.empty());
    CHECK(m.file_associations.empty());
}

TEST_CASE("byte-vector overload matches the text overload") {
    lexe::test::TempLexeHome home;
    const std::string text = base_manifest().dump();
    const std::vector<std::uint8_t> bytes(text.begin(), text.end());
    CHECK(same_manifest(Manifest::parse(bytes), Manifest::parse(text)));

    CHECK_THROWS_AS(Manifest::parse(std::vector<std::uint8_t>{}),
                    VerificationError);
}

TEST_CASE("reject: malformed documents") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(Manifest::parse("{ not json"), VerificationError);
    CHECK_THROWS_AS(Manifest::parse(""), VerificationError);
    CHECK_THROWS_AS(Manifest::parse("[]"), VerificationError);
    CHECK_THROWS_AS(Manifest::parse("\"just a string\""), VerificationError);
    CHECK_THROWS_AS(Manifest::parse("null"), VerificationError);

    // FORMAT-0.1 §5: UTF-8 JSON, no BOM.
    std::string with_bom = "\xEF\xBB\xBF" + base_manifest().dump();
    CHECK_THROWS_AS(Manifest::parse(with_bom), VerificationError);
    const std::vector<std::uint8_t> bom_bytes(with_bom.begin(), with_bom.end());
    CHECK_THROWS_AS(Manifest::parse(bom_bytes), VerificationError);

    // Invalid UTF-8 inside a string value.
    std::string bad_utf8 = base_manifest().dump();
    bad_utf8.replace(bad_utf8.find("Example Application"), 7, "\xFF\xFE_5678");
    CHECK_THROWS_AS(Manifest::parse(bad_utf8), VerificationError);
}

TEST_CASE("reject: every required field missing or null") {
    lexe::test::TempLexeHome home;
    check_rejects({
        {"no lexeVersion", [](json& j) { j.erase("lexeVersion"); }},
        {"null lexeVersion", [](json& j) { j["lexeVersion"] = nullptr; }},
        {"no id", [](json& j) { j.erase("id"); }},
        {"no name", [](json& j) { j.erase("name"); }},
        {"no version", [](json& j) { j.erase("version"); }},
        {"no publisher", [](json& j) { j.erase("publisher"); }},
        {"no publisher.name", [](json& j) { j["publisher"].erase("name"); }},
        {"no publisher.publicKey",
         [](json& j) { j["publisher"].erase("publicKey"); }},
        {"no applicationType", [](json& j) { j.erase("applicationType"); }},
        {"no architectures", [](json& j) { j.erase("architectures"); }},
        {"no entrypoint", [](json& j) { j.erase("entrypoint"); }},
        {"no entrypoint.executable",
         [](json& j) { j["entrypoint"].erase("executable"); }},
        {"no install", [](json& j) { j.erase("install"); }},
        {"no install.mode", [](json& j) { j["install"].erase("mode"); }},
    });
}

TEST_CASE("reject: lexeVersion constraint (MUST be the string \"0.1\")") {
    lexe::test::TempLexeHome home;
    check_rejects({
        {"other version", [](json& j) { j["lexeVersion"] = "0.2"; }},
        {"padded", [](json& j) { j["lexeVersion"] = "0.1.0"; }},
        {"number not string", [](json& j) { j["lexeVersion"] = 0.1; }},
        {"empty", [](json& j) { j["lexeVersion"] = ""; }},
    });
}

TEST_CASE("id: reverse-DNS accept/reject table") {
    lexe::test::TempLexeHome home;
    check_accepts({
        {"two segments", [](json& j) { j["id"] = "example.app"; }},
        {"many segments", [](json& j) { j["id"] = "io.gitlab.team.app"; }},
        {"hyphens digits uppercase",
         [](json& j) { j["id"] = "Com.Example-2.App-x64"; }},
        {"exactly 255 chars",
         [](json& j) { j["id"] = "com." + std::string(251, 'a'); }},
    });
    check_rejects({
        {"empty", [](json& j) { j["id"] = ""; }},
        {"single segment", [](json& j) { j["id"] = "application"; }},
        {"trailing dot", [](json& j) { j["id"] = "com.example."; }},
        {"leading dot", [](json& j) { j["id"] = ".com.example"; }},
        {"empty middle segment", [](json& j) { j["id"] = "com..example"; }},
        {"underscore", [](json& j) { j["id"] = "com.example_app"; }},
        {"space", [](json& j) { j["id"] = "com.exa mple"; }},
        {"slash", [](json& j) { j["id"] = "com.example/app"; }},
        {"non-ascii", [](json& j) { j["id"] = "com.exämple"; }},
        {"256 chars",
         [](json& j) { j["id"] = "com." + std::string(252, 'a'); }},
        {"not a string", [](json& j) { j["id"] = 42; }},
    });
}

TEST_CASE("reject: name / version / publisher constraints") {
    lexe::test::TempLexeHome home;
    check_rejects({
        {"empty name", [](json& j) { j["name"] = ""; }},
        {"name not a string", [](json& j) { j["name"] = 42; }},
        {"empty version", [](json& j) { j["version"] = ""; }},
        {"version not a string", [](json& j) { j["version"] = 1.42; }},
        {"publisher not an object", [](json& j) { j["publisher"] = "Corp"; }},
        {"empty publisher.name",
         [](json& j) { j["publisher"]["name"] = ""; }},
        {"publisher.name not a string",
         [](json& j) { j["publisher"]["name"] = 7; }},
        {"empty publisher.publicKey",
         [](json& j) { j["publisher"]["publicKey"] = ""; }},
        {"publisher.publicKey not a string",
         [](json& j) { j["publisher"]["publicKey"] = 42; }},
        {"publisher.website not a string",
         [](json& j) { j["publisher"]["website"] = 1; }},
    });
}

TEST_CASE("publicKey format is NOT parse's job (verification stage 3)") {
    // FORMAT-0.1 §6 separates stage 2 (manifest §5) from stage 3 (key
    // decode §4): a present, non-empty string passes parse; decoding is
    // decoded_public_key(). SPEC.md's own example uses "ed25519:...".
    lexe::test::TempLexeHome home;
    check_accepts({
        {"undecodable placeholder key",
         [](json& j) { j["publisher"]["publicKey"] = "ed25519:..."; }},
        {"wrong prefix still parses",
         [](json& j) { j["publisher"]["publicKey"] = "rsa:abc"; }},
    });
}

TEST_CASE("reject: applicationType gating (only \"native\" in 0.1)") {
    lexe::test::TempLexeHome home;
    for (const char* type : {"wine", "web", "launcher", "Native", ""}) {
        CAPTURE(type);
        json j = base_manifest();
        j["applicationType"] = type;
        CHECK_THROWS_AS(parse_json(j), VerificationError);
    }
    json j = base_manifest();
    j["applicationType"] = 3;
    CHECK_THROWS_AS(parse_json(j), VerificationError);
}

TEST_CASE("architectures accept/reject table") {
    lexe::test::TempLexeHome home;
    check_accepts({
        {"x86_64 only",
         [](json& j) { j["architectures"] = json::array({"x86_64"}); }},
        {"aarch64 only",
         [](json& j) { j["architectures"] = json::array({"aarch64"}); }},
        {"duplicates allowed",
         [](json& j) {
             j["architectures"] = json::array({"x86_64", "x86_64"});
         }},
    });
    check_rejects({
        {"empty array",
         [](json& j) { j["architectures"] = json::array(); }},
        {"string not array", [](json& j) { j["architectures"] = "x86_64"; }},
        {"non-string element",
         [](json& j) { j["architectures"] = json::array({42}); }},
        {"unrecognised value",
         [](json& j) { j["architectures"] = json::array({"i386"}); }},
        {"unrecognised value mixed with recognised",
         [](json& j) {
             j["architectures"] = json::array({"x86_64", "riscv64"});
         }},
        {"case matters",
         [](json& j) { j["architectures"] = json::array({"X86_64"}); }},
    });
}

TEST_CASE("entrypoint path-safety accept/reject table") {
    lexe::test::TempLexeHome home;
    check_accepts({
        {"flat file",
         [](json& j) { j["entrypoint"]["executable"] = "example"; }},
        {"nested path",
         [](json& j) { j["entrypoint"]["executable"] = "bin/sub/dir/run"; }},
        {"dots inside a filename are not a .. segment",
         [](json& j) { j["entrypoint"]["executable"] = "bin/foo..bar"; }},
    });
    check_rejects({
        {"empty", [](json& j) { j["entrypoint"]["executable"] = ""; }},
        {"absolute",
         [](json& j) { j["entrypoint"]["executable"] = "/usr/bin/evil"; }},
        {"leading ..",
         [](json& j) { j["entrypoint"]["executable"] = "../evil"; }},
        {"embedded ..",
         [](json& j) {
             j["entrypoint"]["executable"] = "bin/../../evil";
         }},
        {"lone ..", [](json& j) { j["entrypoint"]["executable"] = ".."; }},
        {"backslash",
         [](json& j) { j["entrypoint"]["executable"] = "bin\\evil.exe"; }},
        {"drive designator",
         [](json& j) { j["entrypoint"]["executable"] = "C:/evil"; }},
        {"empty segment",
         [](json& j) { j["entrypoint"]["executable"] = "bin//run"; }},
        {"trailing slash",
         [](json& j) { j["entrypoint"]["executable"] = "bin/"; }},
        {"embedded NUL",
         [](json& j) {
             j["entrypoint"]["executable"] = std::string("bin\0run", 7);
         }},
        {"not a string", [](json& j) { j["entrypoint"]["executable"] = 9; }},
        {"entrypoint not an object",
         [](json& j) { j["entrypoint"] = "bin/example"; }},
    });
}

TEST_CASE("reject: entrypoint.arguments type errors") {
    lexe::test::TempLexeHome home;
    check_rejects({
        {"arguments not an array",
         [](json& j) { j["entrypoint"]["arguments"] = "--fast"; }},
        {"non-string argument",
         [](json& j) {
             j["entrypoint"]["arguments"] = json::array({"--ok", 42});
         }},
    });
    check_accepts({
        {"string arguments",
         [](json& j) {
             j["entrypoint"]["arguments"] = json::array({"--flag", ""});
         }},
    });
}

TEST_CASE("install.mode gating: network/launcher are \"unsupported in 0.1\"") {
    lexe::test::TempLexeHome home;
    {
        json j = base_manifest();
        j["install"]["mode"] = "network";
        CHECK_THROWS_WITH_AS(parse_json(j),
                             doctest::Contains("unsupported in 0.1"),
                             VerificationError);
    }
    {
        json j = base_manifest();
        j["install"]["mode"] = "launcher";
        CHECK_THROWS_WITH_AS(parse_json(j),
                             doctest::Contains("unsupported in 0.1"),
                             VerificationError);
    }
    check_rejects({
        {"unknown mode", [](json& j) { j["install"]["mode"] = "portable"; }},
        {"case matters", [](json& j) { j["install"]["mode"] = "Bundled"; }},
        {"empty mode", [](json& j) { j["install"]["mode"] = ""; }},
        {"mode not a string", [](json& j) { j["install"]["mode"] = 1; }},
        {"install not an object", [](json& j) { j["install"] = "bundled"; }},
    });
}

TEST_CASE("install.scope and install.estimatedSize constraints") {
    lexe::test::TempLexeHome home;
    check_accepts({
        {"scope system parses (not gated by §5)",
         [](json& j) { j["install"]["scope"] = "system"; }},
        {"estimatedSize zero",
         [](json& j) { j["install"]["estimatedSize"] = 0; }},
        {"estimatedSize large",
         [](json& j) {
             j["install"]["estimatedSize"] = 9007199254740993ull;
         }},
    });
    check_rejects({
        {"scope not a string", [](json& j) { j["install"]["scope"] = 5; }},
        {"scope empty", [](json& j) { j["install"]["scope"] = ""; }},
        {"estimatedSize negative",
         [](json& j) { j["install"]["estimatedSize"] = -5; }},
        {"estimatedSize float",
         [](json& j) { j["install"]["estimatedSize"] = 1.5; }},
        {"estimatedSize string",
         [](json& j) { j["install"]["estimatedSize"] = "126MB"; }},
    });
}

TEST_CASE("reject: permissions / updates / integration type errors") {
    lexe::test::TempLexeHome home;
    check_rejects({
        {"permissions not an array",
         [](json& j) { j["permissions"] = "network"; }},
        {"non-string permission",
         [](json& j) { j["permissions"] = json::array({42}); }},
        {"updates not an object", [](json& j) { j["updates"] = "yes"; }},
        {"updates.enabled not a bool",
         [](json& j) { j["updates"]["enabled"] = "true"; }},
        {"updates.channel not a string",
         [](json& j) { j["updates"]["channel"] = 3; }},
        {"updates.manifest not a string",
         [](json& j) { j["updates"]["manifest"] = 3; }},
        {"updates.allowSourceChange not a bool",
         [](json& j) { j["updates"]["allowSourceChange"] = 1; }},
        {"integration not an object", [](json& j) { j["integration"] = 7; }},
        {"desktopEntry not a bool",
         [](json& j) { j["integration"]["desktopEntry"] = "yes"; }},
        {"categories not an array",
         [](json& j) { j["integration"]["categories"] = "Utility"; }},
        {"non-string category",
         [](json& j) {
             j["integration"]["categories"] = json::array({1});
         }},
        {"fileAssociations not an array",
         [](json& j) { j["integration"]["fileAssociations"] = "x"; }},
        {"fileAssociation not an object",
         [](json& j) {
             j["integration"]["fileAssociations"] = json::array({".ex"});
         }},
        {"fileAssociation missing mimeType",
         [](json& j) {
             j["integration"]["fileAssociations"] =
                 json::array({{{"extension", ".ex"}}});
         }},
        {"fileAssociation missing extension",
         [](json& j) {
             j["integration"]["fileAssociations"] =
                 json::array({{{"mimeType", "application/x-ex"}}});
         }},
        {"fileAssociation empty extension",
         [](json& j) {
             j["integration"]["fileAssociations"] = json::array(
                 {{{"extension", ""}, {"mimeType", "application/x-ex"}}});
         }},
    });
}

TEST_CASE("unknown fields are ignored at every level (forward compat)") {
    lexe::test::TempLexeHome home;
    check_accepts({
        {"unknown top-level field",
         [](json& j) { j["futureFeature"] = {{"x", 1}}; }},
        {"unknown publisher field",
         [](json& j) { j["publisher"]["pgpKey"] = "0xDEAD"; }},
        {"unknown entrypoint field",
         [](json& j) { j["entrypoint"]["shell"] = false; }},
        {"unknown install field",
         [](json& j) { j["install"]["compression"] = "zstd"; }},
        {"unknown updates field",
         [](json& j) { j["updates"]["delta"] = true; }},
        {"unknown integration field",
         [](json& j) { j["integration"]["protocols"] = json::array(); }},
        {"unknown fileAssociation field",
         [](json& j) {
             j["integration"]["fileAssociations"][0]["icon"] = "doc.png";
         }},
    });
    // Values of unknown fields do not leak into the parsed struct.
    json j = base_manifest();
    j["permissionsV2"] = json::array({"everything"});
    const Manifest m = parse_json(j);
    CHECK(m.permissions ==
          std::vector<std::string>{"network", "user-files-selected"});
}

TEST_CASE("round-trip: SPEC example -> to_json -> parse is field-identical") {
    lexe::test::TempLexeHome home;
    const Manifest original = Manifest::parse(kSpecExample);
    const std::string serialized = original.to_json();
    const Manifest reparsed = Manifest::parse(serialized);
    CHECK(same_manifest(original, reparsed));
}

TEST_CASE("round-trip: minimal manifest keeps its defaults") {
    lexe::test::TempLexeHome home;
    const json minimal = {
        {"lexeVersion", "0.1"},
        {"id", "org.example.app"},
        {"name", "App"},
        {"version", "2.0"},
        {"publisher",
         {{"name", "P"},
          {"publicKey",
           "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}},
        {"applicationType", "native"},
        {"architectures", json::array({"aarch64"})},
        {"entrypoint", {{"executable", "run.sh"}}},
        {"install", {{"mode", "bundled"}}},
    };
    const Manifest original = parse_json(minimal);
    const Manifest reparsed = Manifest::parse(original.to_json());
    CHECK(same_manifest(original, reparsed));
}

TEST_CASE("round-trip: fully populated manifest") {
    lexe::test::TempLexeHome home;
    json j = base_manifest();
    j["entrypoint"]["arguments"] = json::array({"--profile", "release", ""});
    j["updates"]["enabled"] = false;
    j["updates"]["channel"] = "nightly";
    j["integration"]["desktopEntry"] = false;
    j["integration"]["categories"] = json::array({"Game", "Utility"});
    j["integration"]["fileAssociations"] = json::array(
        {{{"extension", ".sav"}, {"mimeType", "application/x-sav"}},
         {{"extension", ".map"}, {"mimeType", "application/x-map"}}});
    const Manifest original = parse_json(j);
    const Manifest reparsed = Manifest::parse(original.to_json());
    CHECK(same_manifest(original, reparsed));
}

TEST_CASE("to_json emits the SPEC.md manifest shape") {
    lexe::test::TempLexeHome home;
    const Manifest m = Manifest::parse(kSpecExample);
    const json doc = json::parse(m.to_json());

    CHECK(doc["lexeVersion"] == "0.1");
    CHECK(doc["publisher"]["name"] == "Example Corporation");
    CHECK(doc["publisher"]["website"] == "https://example.com");
    CHECK(doc["publisher"]["publicKey"] == "ed25519:...");
    CHECK(doc["architectures"] == json::array({"x86_64", "aarch64"}));
    CHECK(doc["entrypoint"]["executable"] == "bin/example");
    CHECK(doc["entrypoint"]["arguments"].is_array());
    CHECK(doc["install"]["scope"] == "user");
    CHECK(doc["install"]["mode"] == "bundled");
    CHECK(doc["install"]["estimatedSize"] == 125829120);
    CHECK(doc["updates"]["enabled"] == true);
    CHECK(doc["updates"]["manifest"] ==
          "https://example.com/releases/update.json");
    CHECK(doc["integration"]["fileAssociations"][0]["extension"] ==
          ".example");
    CHECK(doc["integration"]["fileAssociations"][0]["mimeType"] ==
          "application/x-example");
}

TEST_CASE("to_json omits not-provided optionals") {
    lexe::test::TempLexeHome home;
    Manifest m = Manifest::parse(kSpecExample);
    m.publisher_website.clear();
    m.install_estimated_size = 0; // 0 = not provided
    m.updates_manifest_url.clear();
    const json doc = json::parse(m.to_json());
    CHECK_FALSE(doc["publisher"].contains("website"));
    CHECK_FALSE(doc["install"].contains("estimatedSize"));
    CHECK_FALSE(doc["updates"].contains("manifest"));
}

TEST_CASE("decoded_public_key rejects malformed key strings") {
    // Throws lexe::Error both from the real crypto module
    // (VerificationError) and from its pre-implementation stub.
    lexe::test::TempLexeHome home;
    Manifest m = Manifest::parse(kSpecExample);

    m.publisher_public_key = "ed25519:..."; // not base64
    CHECK_THROWS_AS(m.decoded_public_key(), Error);
    m.publisher_public_key = "rsa:AAAA";    // wrong prefix
    CHECK_THROWS_AS(m.decoded_public_key(), Error);
    m.publisher_public_key = "ed25519:AAAA"; // decodes to 3 bytes, not 32
    CHECK_THROWS_AS(m.decoded_public_key(), Error);
}

TEST_CASE("decoded_public_key decodes a valid key (via crypto module)") {
    lexe::test::TempLexeHome home;
    Manifest m = Manifest::parse(kSpecExample);
    m.publisher_public_key =
        "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 zeros
    try {
        const lexe::crypto::PublicKey key = m.decoded_public_key();
        CHECK(key == lexe::crypto::PublicKey{});
    } catch (const Error& e) {
        // The crypto module may still be a stub in early build waves; a
        // decode failure for this structurally valid key is only OK then.
        const std::string what = e.what();
        if (what.find("not implemented") != std::string::npos) {
            MESSAGE("crypto module not implemented yet; decode not checked");
        } else {
            FAIL("unexpected error decoding a valid key: " << what);
        }
    }
}

} // TEST_SUITE("manifest")
