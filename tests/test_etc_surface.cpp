// The /etc contract.
//
// The sandbox's /etc is an ALLOWLIST — eight entries chosen for dynamic
// linking and name resolution, plus a few gated on the `network` permission.
// Nothing in the suite asserted anything about it, so what an application can
// and cannot read out of /etc could change, or be chosen wrong, with no check
// to notice. Two things were found that way and both are pinned here:
//
//   * a granted `network` permission produced a network on which no ordinary
//     Linux TLS client could verify a certificate, because the trust store was
//     not on the list (measured: `https://example.com/` -> curl exit 77,
//     "error setting certificate file"; the same URL with `-k` -> 200). That
//     is fixed, and the fix is pinned below;
//
//   * the reduction also removes an application's own host-installed security
//     policy. Measured on Ubuntu 24.04: ImageMagick reports
//     `/etc/ImageMagick-6/policy.xml` directly and `[built-in]` inside the
//     sandbox, and `convert label:@m.txt info:` — indirect file read, which
//     Ubuntu's policy denies — exits 1 directly and 0 inside. That is NOT
//     fixed; it is documented in docs/THREAT-MODEL.md as an explicit
//     non-guarantee, and the ABSENT assertions below are what make it
//     impossible to change that quietly in either direction.
//
// Three layers, deliberately: the rendered plan (pure, every platform), the
// warning that fires when a host has no trust store at all (pure, fabricated
// sysroot), and a real bubblewrap sandbox whose probe calls access() from the
// inside (Linux). The last one is the only one that proves anything about the
// operating system; the first two are its observers, and they do not skip.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/paths.hpp"
#include "lexe/base/util.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/package/package.hpp"
#include "lexe/runtime/launcher.hpp"
#include "lexe/sandbox/isolation.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace lexe;

namespace {

// ---------------------------------------------------------------- the list

/// What the contract says about one /etc path.
enum class Visibility {
    Always,      // on the linking / name-resolution allowlist
    NetworkOnly, // bound only when the `network` permission is granted
    GuiOnly,     // bound only for launch.mode "gui" (rendering resources)
    Never,       // deliberately reduced away — see docs/THREAT-MODEL.md #12
};

struct EtcEntry {
    const char* path;
    Visibility visibility;
    const char* why;
};

/// The pinned contract. `Never` entries are the interesting ones: each is a
/// file a real application reads on an ordinary Ubuntu host, and each is
/// invisible inside the sandbox.
const std::vector<EtcEntry>& contract() {
    static const std::vector<EtcEntry> entries = {
        {"/etc/ld.so.cache", Visibility::Always, "dynamic linking"},
        {"/etc/ld.so.conf", Visibility::Always, "dynamic linking"},
        {"/etc/ld.so.conf.d", Visibility::Always, "dynamic linking"},
        {"/etc/passwd", Visibility::Always, "name resolution (getpwuid)"},
        {"/etc/group", Visibility::Always, "name resolution (getgrgid)"},
        {"/etc/nsswitch.conf", Visibility::Always, "name resolution"},
        {"/etc/alternatives", Visibility::Always, "Debian alternatives symlinks"},
        {"/etc/localtime", Visibility::Always, "local time"},

        {"/etc/resolv.conf", Visibility::NetworkOnly, "DNS servers"},
        {"/etc/hosts", Visibility::NetworkOnly, "static name resolution"},
        {"/etc/ssl/certs/ca-certificates.crt", Visibility::NetworkOnly,
         "the system TLS trust store: without it a granted `network` "
         "permission yields a network on which nothing can verify a "
         "certificate"},

        {"/etc/ImageMagick-6/policy.xml", Visibility::Never,
         "an application's own host-installed security policy — the witness "
         "for THREAT-MODEL.md #12"},
        {"/etc/mime.types", Visibility::Never, "content-type database"},
        {"/etc/timezone", Visibility::Never, "the host's timezone name"},
        {"/etc/hostname", Visibility::Never, "the host's name"},
        // These two arrive with the GUI reduction, and NOT with a console or
        // service launch. Worth being explicit about, because `launch.mode`
        // DEFAULTS to "gui": a manifest that declares no mode at all gets
        // them, which is not what ISOLATION.md's "declares launch.mode gui"
        // reads as. /etc/machine-id in particular is a stable per-device
        // identifier, so this is the difference between a console application
        // that can fingerprint the machine and one that cannot.
        {"/etc/machine-id", Visibility::GuiOnly,
         "a stable per-device identifier (fontconfig cache key)"},
        {"/etc/fonts", Visibility::GuiOnly, "font configuration"},
        {"/etc/os-release", Visibility::Never,
         "which distribution and version the host runs"},
    };
    return entries;
}

// ------------------------------------------------------- pure plan helpers

IsolationCapabilities full_caps() {
    IsolationCapabilities c;
    c.status = CapabilityStatus::Available;
    c.backend_present = true;
    c.user_namespaces = true;
    c.network_namespaces = true;
    c.bind_mounts = true;
    return c;
}

IsolationRequest sample_request(bool network) {
    IsolationRequest r;
    r.app_id = "com.example.app";
    r.app_root = "/lexehome/apps/com.example.app/versions/1.0.0";
    r.entrypoint = r.app_root / "bin/app";
    r.data_root = "/lexehome/data/com.example.app";
    r.cache_root = "/lexehome/cache/apps/com.example.app";
    r.network_allowed = network;
    return r;
}

/// Every host path under /etc that the plan binds, sorted. This is the whole
/// /etc surface the sandbox can possibly have: bwrap creates nothing else
/// there, and the root is remounted read-only afterwards.
std::vector<std::string> etc_binds(const IsolationPlan& plan) {
    std::vector<std::string> out;
    for (const BindMount& b : plan.binds) {
        if (b.host.rfind("/etc/", 0) == 0 || b.host == "/etc") {
            out.push_back(b.host);
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

} // namespace

TEST_SUITE("etc_surface") {

// ---------------------------------------------------------------------------
// 1. The plan. Exact set, no more and no less — an added bind fails this just
//    as loudly as a removed one, because an addition to /etc is a widening of
//    what the application can see about the host and must be argued for.
// ---------------------------------------------------------------------------

TEST_CASE("the /etc allowlist is exactly the linking and name-resolution set") {
    lexe::test::TempLexeHome home;
    const IsolationPlan plan = build_plan(sample_request(false), full_caps());

    const std::vector<std::string> expected = {
        "/etc/alternatives", "/etc/group",     "/etc/ld.so.cache",
        "/etc/ld.so.conf",   "/etc/ld.so.conf.d", "/etc/localtime",
        "/etc/nsswitch.conf", "/etc/passwd"};
    CHECK(etc_binds(plan) == expected);

    // Every one of them is read-only and optional: /etc is never writable from
    // inside, and a host that lays one of these out differently skips it
    // rather than failing to launch.
    for (const BindMount& b : plan.binds) {
        if (b.host.rfind("/etc/", 0) != 0) continue;
        CAPTURE(b.host);
        CHECK(b.read_only);
        CHECK(b.optional);
        CHECK(b.sandbox == b.host); // bound at its real path, never remapped
    }
}

TEST_CASE("the `network` permission adds name resolution AND the trust store") {
    lexe::test::TempLexeHome home;
    const IsolationPlan plan = build_plan(sample_request(true), full_caps());

    const std::vector<std::string> expected = {
        "/etc/alternatives",   "/etc/ca-certificates", "/etc/group",
        "/etc/hosts",          "/etc/ld.so.cache",     "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",   "/etc/localtime",       "/etc/nsswitch.conf",
        "/etc/passwd",         "/etc/pki/ca-trust",    "/etc/pki/tls",
        "/etc/resolv.conf",    "/etc/ssl/certs",       "/etc/ssl/openssl.cnf"};
    CHECK(etc_binds(plan) == expected);

    // Rendered as optional read-only binds, so a host with a different trust
    // layout skips the entries it does not have instead of refusing to start.
    const std::vector<std::string> argv =
        render_bwrap_argv(plan, "/usr/bin/bwrap");
    for (const std::string& p : tls_trust_store_paths()) {
        CAPTURE(p);
        const auto it = std::find(argv.begin(), argv.end(), p);
        REQUIRE(it != argv.end());
        CHECK(*(it - 1) == "--ro-bind-try");
    }
}

TEST_CASE("no trust store reaches an application without the permission") {
    lexe::test::TempLexeHome home;
    const IsolationPlan plan = build_plan(sample_request(false), full_caps());
    const std::vector<std::string> etc = etc_binds(plan);
    for (const std::string& p : tls_trust_store_paths()) {
        CAPTURE(p);
        CHECK(std::find(etc.begin(), etc.end(), p) == etc.end());
        // /var/lib/ca-certificates is not under /etc, so check the whole bind
        // list too rather than only the /etc slice.
        CHECK(std::none_of(plan.binds.begin(), plan.binds.end(),
                           [&](const BindMount& b) { return b.host == p; }));
    }
}

TEST_CASE("a GUI launch adds exactly two /etc entries, and one is an identifier") {
    lexe::test::TempLexeHome home;
    IsolationRequest r = sample_request(false);
    r.gui = true;
    const std::vector<std::string> etc = etc_binds(build_plan(r, full_caps()));

    const std::vector<std::string> expected = {
        "/etc/alternatives", "/etc/fonts",        "/etc/group",
        "/etc/ld.so.cache",  "/etc/ld.so.conf",   "/etc/ld.so.conf.d",
        "/etc/localtime",    "/etc/machine-id",   "/etc/nsswitch.conf",
        "/etc/passwd"};
    CHECK(etc == expected);

    // Called out on its own because it is the one with a privacy cost:
    // `launch.mode` DEFAULTS to "gui" in FORMAT 0.1, so a manifest that
    // declares no mode at all receives /etc/machine-id — a stable per-device
    // identifier — and its publisher never made that choice. ISOLATION.md used
    // to say display access went to an application that "declares"
    // launch.mode gui, which reads as though silence meant no.
    CHECK(std::find(etc.begin(), etc.end(), "/etc/machine-id") != etc.end());
}

TEST_CASE("a build gets no trust store even with the permission") {
    lexe::test::TempLexeHome home;
    // A build's network is denied unconditionally (a build that downloads is
    // fetching unsigned code behind a signature that says nothing about it),
    // so there is nothing for a trust store to be for.
    IsolationRequest r = sample_request(true);
    r.build = true;
    const std::vector<std::string> etc =
        etc_binds(build_plan(r, full_caps()));
    CHECK(std::find(etc.begin(), etc.end(), "/etc/ssl/certs") == etc.end());
    CHECK(std::find(etc.begin(), etc.end(), "/etc/resolv.conf") == etc.end());
}

// ---------------------------------------------------------------------------
// 2. The diagnostic. The trust-store binds are OPTIONAL, which means a host
//    that has none of them produces a sandbox that starts perfectly and fails
//    every certificate check inside it — the silent failure the bind was added
//    to prevent, reintroduced by the bind's own error handling. A fabricated
//    sysroot is what lets this be tested on a machine that is configured
//    correctly.
// ---------------------------------------------------------------------------

TEST_CASE("a host with no trust store is warned about, not left to find out") {
    lexe::test::TempLexeHome home;
    const fs::path root = home.path() / "sysroot";
    fs::create_directories(root / "etc" / "ssl" / "certs");

    const IsolationPlan net = build_plan(sample_request(true), full_caps());
    const IsolationPlan no_net = build_plan(sample_request(false), full_caps());

    // Empty /etc/ssl/certs, no bundle anywhere: nothing to bind.
    CHECK_FALSE(tls_trust_store_present(root));
    const std::string warning = tls_trust_store_warning(net, root);
    CHECK_FALSE(warning.empty());
    CHECK(warning.find("network") != std::string::npos);
    CHECK(warning.find("trust store") != std::string::npos);

    // An application with no network permission is not warned: it was never
    // promised a working network, so there is nothing broken to report.
    CHECK(tls_trust_store_warning(no_net, root).empty());

    // A bundle file is enough.
    util::spit(root / "etc" / "ssl" / "certs" / "ca-certificates.crt",
               std::string_view("-----BEGIN CERTIFICATE-----\n"));
    CHECK(tls_trust_store_present(root));
    CHECK(tls_trust_store_warning(net, root).empty());

    // …and so is a populated hashed CApath with no bundle file, because a
    // client configured that way verifies with it and nothing else.
    fs::remove(root / "etc" / "ssl" / "certs" / "ca-certificates.crt");
    CHECK_FALSE(tls_trust_store_present(root));
    util::spit(root / "etc" / "ssl" / "certs" / "3513523f.0",
               std::string_view("-----BEGIN CERTIFICATE-----\n"));
    CHECK(tls_trust_store_present(root));
    CHECK(tls_trust_store_warning(net, root).empty());
}

TEST_CASE("the Fedora trust layout also counts as present") {
    lexe::test::TempLexeHome home;
    const fs::path root = home.path() / "sysroot";
    fs::create_directories(root / "etc" / "pki" / "tls" / "certs");
    CHECK_FALSE(tls_trust_store_present(root));
    util::spit(root / "etc" / "pki" / "tls" / "certs" / "ca-bundle.crt",
               std::string_view("-----BEGIN CERTIFICATE-----\n"));
    CHECK(tls_trust_store_present(root));
}

// ---------------------------------------------------------------------------
// 3. The operating system. Everything above describes an intention; this runs
//    a real bubblewrap sandbox through the real launcher and asks the kernel.
// ---------------------------------------------------------------------------

#ifndef _WIN32

namespace {

bool isolation_available(const Paths& paths) {
    return make_isolation_backend(paths)->capabilities().status ==
           CapabilityStatus::Available;
}

/// Install a probe whose entrypoint calls access(R_OK) on every path in the
/// contract and writes `<path>=PRESENT|ABSENT` into its private data root.
/// The C source is GENERATED from contract(), so the list the probe measures
/// and the list the assertions use cannot drift apart.
void install_etc_probe(const Paths& paths, const crypto::KeyPair& key,
                       const std::string& id,
                       const std::vector<std::string>& permissions,
                       const std::string& launch_mode, const fs::path& work) {
    std::string list;
    for (const EtcEntry& e : contract()) {
        list += "        \"";
        list += e.path;
        list += "\",\n";
    }
    const std::string source =
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <unistd.h>\n"
        "int main(void) {\n"
        "    const char* paths[] = {\n" + list +
        "        0\n"
        "    };\n"
        "    const char* data = getenv(\"LEXE_APP_DATA\");\n"
        "    char out[4096];\n"
        "    if (!data) return 2;\n"
        "    snprintf(out, sizeof out, \"%s/etc-report\", data);\n"
        "    FILE* f = fopen(out, \"w\");\n"
        "    if (!f) return 3;\n"
        "    for (int i = 0; paths[i]; ++i) {\n"
        "        fprintf(f, \"%s=%s\\n\", paths[i],\n"
        "                access(paths[i], R_OK) == 0 ? \"PRESENT\" : \"ABSENT\");\n"
        "    }\n"
        "    fclose(f);\n"
        "    return 0;\n"
        "}\n";

    const fs::path proj = work / ("proj-" + id);
    fs::create_directories(proj / "payload" / "bin");
    REQUIRE(test::compile_native_executable(proj / "payload" / "bin" / "probe",
                                            source));
    nlohmann::json m = {
        {"lexeVersion", "0.1"},
        {"id", id},
        {"name", "EtcProbe"},
        {"version", "1.0.0"},
        {"publisher",
         {{"name", "P"},
          {"publicKey", test::encode_public_key_str(key.public_key)}}},
        {"applicationType", "native"},
        {"architectures", nlohmann::json::array({"x86_64", "aarch64"})},
        {"entrypoint", {{"executable", "bin/probe"}}},
        {"install", {{"scope", "user"}, {"mode", "bundled"}}},
        // Declared, never defaulted: `launch.mode` defaults to "gui", and a
        // probe that let it default would have been measuring the GUI
        // reduction while claiming to measure the console one.
        {"launch", {{"mode", launch_mode}}},
        {"permissions", permissions},
    };
    util::spit(proj / "lexe.json", std::string_view(m.dump(2) + "\n"));

    PackageWriter::Inputs in;
    in.payload_dir = proj / "payload";
    in.manifest_file = proj / "lexe.json";
    const fs::path pkg = work / (id + ".lexe");
    PackageWriter::write(in, key, pkg);
    Installer(paths).install(pkg, InstallOptions{});
}

/// "PRESENT" / "ABSENT" / "" (the probe did not report that path at all).
/// Anchored to a line start so /etc/ld.so.conf cannot answer for
/// /etc/ld.so.conf.d.
std::string reported(const std::string& report, const char* path) {
    const std::string line = std::string("\n") + path + "=";
    const std::string padded = "\n" + report;
    const std::size_t at = padded.find(line);
    if (at == std::string::npos) return {};
    const std::size_t v = at + line.size();
    const std::size_t end = padded.find('\n', v);
    return padded.substr(v, end == std::string::npos ? end : end - v);
}

/// What the probe would have said running directly on this host.
bool readable_on_host(const char* path) {
    return ::access(path, R_OK) == 0;
}

} // namespace

TEST_CASE("the /etc surface inside a real sandbox is the pinned contract") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!isolation_available(paths)) {
        MESSAGE("SKIP: bubblewrap isolation unavailable on this host");
        return;
    }
    if (!test::have_native_compiler()) {
        MESSAGE("SKIP: no host C compiler to build the probe entrypoint");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);

    install_etc_probe(paths, key, "com.example.etc", /*permissions=*/{},
                      "console", work);
    install_etc_probe(paths, key, "com.example.etcnet",
                      /*permissions=*/{"network"}, "console", work);
    install_etc_probe(paths, key, "com.example.etcgui", /*permissions=*/{},
                      "gui", work);
    run_app(paths, "com.example.etc", {});
    run_app(paths, "com.example.etcnet", {});
    run_app(paths, "com.example.etcgui", {});

    const std::string plain =
        util::slurp_text(paths.data_dir() / "com.example.etc" / "etc-report");
    const std::string net =
        util::slurp_text(paths.data_dir() / "com.example.etcnet" / "etc-report");
    const std::string gui =
        util::slurp_text(paths.data_dir() / "com.example.etcgui" / "etc-report");
    REQUIRE_FALSE(plain.empty());
    REQUIRE_FALSE(net.empty());
    REQUIRE_FALSE(gui.empty());

    // A check cannot detect what it holds constant. An entry this host does
    // not have would read ABSENT inside AND outside, and would assert nothing
    // at all — so those are skipped out loud and counted, and the test fails
    // if too few real ones survive.
    int checked_always = 0, checked_network = 0, checked_gui = 0,
        checked_never = 0;

    for (const EtcEntry& e : contract()) {
        INFO("entry: " << std::string(e.path) << " -- " << std::string(e.why));
        REQUIRE(reported(plain, e.path) != "");
        REQUIRE(reported(net, e.path) != "");
        REQUIRE(reported(gui, e.path) != "");
        if (!readable_on_host(e.path)) {
            MESSAGE("SKIP (host does not have it): " << std::string(e.path));
            continue;
        }
        switch (e.visibility) {
            case Visibility::Always:
                CHECK(reported(plain, e.path) == "PRESENT");
                CHECK(reported(net, e.path) == "PRESENT");
                CHECK(reported(gui, e.path) == "PRESENT");
                ++checked_always;
                break;
            case Visibility::NetworkOnly:
                // Both halves matter. "PRESENT with network" alone would still
                // pass if the bind were unconditional, and "ABSENT without"
                // alone would still pass if it were never bound at all — which
                // is precisely the state the trust store was in.
                CHECK(reported(plain, e.path) == "ABSENT");
                CHECK(reported(net, e.path) == "PRESENT");
                CHECK(reported(gui, e.path) == "ABSENT"); // GUI is not network
                ++checked_network;
                break;
            case Visibility::GuiOnly:
                CHECK(reported(plain, e.path) == "ABSENT");
                CHECK(reported(net, e.path) == "ABSENT");
                CHECK(reported(gui, e.path) == "PRESENT");
                ++checked_gui;
                break;
            case Visibility::Never:
                // Readable on the host, invisible inside, with and without the
                // network permission. See docs/THREAT-MODEL.md #12: this is
                // the reduction, pinned so it cannot change unannounced.
                CHECK(reported(plain, e.path) == "ABSENT");
                CHECK(reported(net, e.path) == "ABSENT");
                CHECK(reported(gui, e.path) == "ABSENT");
                ++checked_never;
                break;
        }
    }

    CAPTURE(checked_always);
    CAPTURE(checked_network);
    CAPTURE(checked_gui);
    CAPTURE(checked_never);
    CHECK(checked_always >= 5);
    CHECK(checked_network >= 3); // resolv.conf, hosts, the trust store
    CHECK(checked_gui >= 2);     // /etc/fonts, /etc/machine-id
    CHECK(checked_never >= 3);
}

#endif // _WIN32

} // TEST_SUITE("etc_surface")
