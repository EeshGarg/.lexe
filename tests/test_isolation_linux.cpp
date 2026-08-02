// Linux isolation integration tests (runtime-trust WS7). These run a REAL
// bubblewrap sandbox through the real launcher and prove OS-level denials — a
// sandbox command line existing is not proof; only a demonstrated denial is.
// They skip (with a clear reason) when the backend is genuinely unavailable;
// the fail-closed behaviour is still asserted with the backend hidden.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/isolation.hpp"
#include "core/launcher.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace lexe;

#ifndef _WIN32
namespace {

/// True when the bubblewrap backend actually works on this host.
bool isolation_available(const Paths& paths) {
    return make_isolation_backend(paths)->capabilities().status ==
           CapabilityStatus::Available;
}

/// A one-shot host TCP listener on 127.0.0.1, accepted on a background thread.
struct TcpListener {
    int fd = -1;
    int port = 0;
    std::thread th;
    TcpListener() {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        int on = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // ephemeral
        ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        socklen_t len = sizeof(addr);
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ::ntohs(addr.sin_port);
        ::listen(fd, 1);
        th = std::thread([this] {
            int c = ::accept(fd, nullptr, nullptr);
            if (c >= 0) ::close(c);
        });
    }
    ~TcpListener() {
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
        if (th.joinable()) th.join();
    }
};

/// Build + install (through the real installer, so hashes and permissions are
/// recorded) a probe app that writes a report into its private data root and
/// attempts a network connection to a target it reads from that root.
void install_probe(const Paths& paths, const crypto::KeyPair& key,
                   const std::string& id,
                   const std::vector<std::string>& permissions,
                   const std::string& host_home_marker,
                   const std::string& other_app_marker, const fs::path& work) {
    const std::string script =
        "#!/bin/sh\n"
        "R=\"$LEXE_APP_DATA/report\"\n"
        ": > \"$R\"\n"
        "D=$(dirname \"$0\")\n"
        "{\n"
        "  echo \"cwd:$(pwd)\"\n"
        "  echo \"ldpreload:${LD_PRELOAD:-none}\"\n"
        "  echo \"secret:${LEXE_TEST_SECRET:-none}\"\n"
        "  echo \"pythonpath:${PYTHONPATH:-none}\"\n"
        "  echo \"path:$PATH\"\n"
        "  (echo x 2>/dev/null > \"$D/wtest\" && echo approot:writable || echo approot:ro)\n"
        "  (echo x 2>/dev/null > \"$LEXE_APP_DATA/wtest\" && echo data:writable || echo data:ro)\n"
        "  (echo x 2>/dev/null > \"$LEXE_APP_CACHE/wtest\" && echo cache:writable || echo cache:ro)\n"
        "  (echo x 2>/dev/null > \"$TMPDIR/wtest\" && echo temp:writable || echo temp:ro)\n"
        "  (cat \"" + host_home_marker + "\" >/dev/null 2>&1 && echo home:visible || echo home:hidden)\n"
        "  (cat \"" + other_app_marker + "\" >/dev/null 2>&1 && echo crossapp:visible || echo crossapp:hidden)\n"
        "} >> \"$R\"\n"
        "T=$(cat \"$LEXE_APP_DATA/target\" 2>/dev/null)\n"
        "/usr/bin/python3 -c \"import socket,sys\n"
        "h,p=sys.argv[1].rsplit(':',1)\n"
        "s=socket.socket(); s.settimeout(3)\n"
        "try: s.connect((h,int(p))); print('net:connected')\n"
        "except OSError as e: print('net:errno:'+str(e.errno))\" \"$T\" >> \"$R\" 2>&1\n";

    const fs::path proj = work / ("proj-" + id);
    fs::create_directories(proj / "payload" / "bin");
    util::spit(proj / "payload" / "bin" / "probe", std::string_view(script));
    std::error_code ec;
    fs::permissions(proj / "payload" / "bin" / "probe",
                    fs::perms::owner_all | fs::perms::group_read |
                        fs::perms::group_exec | fs::perms::others_read |
                        fs::perms::others_exec,
                    ec);
    nlohmann::json m = {
        {"lexeVersion", "0.1"},
        {"id", id},
        {"name", "Probe"},
        {"version", "1.0.0"},
        {"publisher",
         {{"name", "P"}, {"publicKey", test::encode_public_key_str(key.public_key)}}},
        {"applicationType", "native"},
        {"architectures", nlohmann::json::array({"x86_64", "aarch64"})},
        {"entrypoint", {{"executable", "bin/probe"}}},
        {"install", {{"scope", "user"}, {"mode", "bundled"}}},
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

std::string read_report(const Paths& paths, const std::string& id) {
    const fs::path r = paths.data_dir() / id / "report";
    return fs::is_regular_file(r) ? util::slurp_text(r) : std::string();
}

bool report_has(const std::string& report, const std::string& line) {
    return report.find(line) != std::string::npos;
}

} // namespace

TEST_SUITE("isolation_linux") {

TEST_CASE("no-network app: filesystem/home/cross-app/env/network all denied") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!isolation_available(paths)) {
        MESSAGE("SKIP: bubblewrap isolation unavailable on this host "
                "(unprivileged user namespaces / netns)");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);

    // A real host-home file, and another installed app's private data.
    const fs::path host_marker =
        fs::path(util::get_env("HOME").value_or("/home/lexe")) /
        (".lexe-itest-secret-" + std::to_string(::getpid()));
    util::spit(host_marker, std::string_view("HOST-HOME-SECRET\n"));
    const fs::path other_data = paths.data_dir() / "com.other.app";
    util::spit(other_data / "secret", std::string_view("OTHER-APP-SECRET\n"));

    install_probe(paths, key, "com.example.probe", /*permissions=*/{},
                  host_marker.string(), (other_data / "secret").string(), work);

    // Network target: a routable non-loopback address (unreachable in an
    // isolated network namespace).
    util::spit(paths.data_dir() / "com.example.probe" / "target",
               std::string_view("10.255.255.1:9"));

    // Dangerous variables in the CALLER environment must be stripped.
    util::set_env("LD_PRELOAD", "/evil.so");
    util::set_env("LEXE_TEST_SECRET", "hunter2");
    util::set_env("PYTHONPATH", "/attacker");
    run_app(paths, "com.example.probe", {});
    util::unset_env("LD_PRELOAD");
    util::unset_env("LEXE_TEST_SECRET");
    util::unset_env("PYTHONPATH");

    const std::string r = read_report(paths, "com.example.probe");
    REQUIRE_FALSE(r.empty());
    CHECK(report_has(r, "approot:ro"));        // installed root read-only
    CHECK(report_has(r, "data:writable"));     // private data writable
    CHECK(report_has(r, "cache:writable"));    // private cache writable
    CHECK(report_has(r, "temp:writable"));     // private temp writable
    CHECK(report_has(r, "home:hidden"));       // real host home not visible
    CHECK(report_has(r, "crossapp:hidden"));   // another app's data not visible
    CHECK(report_has(r, "ldpreload:none"));    // LD_PRELOAD neutralized
    CHECK(report_has(r, "secret:none"));       // secret stripped
    CHECK(report_has(r, "pythonpath:none"));   // PYTHONPATH stripped
    CHECK(report_has(r, "path:/usr/bin:/bin"));// PATH fixed
    CHECK(report_has(r, "cwd:/run/lexe/data"));// not the caller's cwd
    CHECK(report_has(r, "net:errno:101"));     // ENETUNREACH: no network

    std::error_code ec;
    fs::remove(host_marker, ec);
}

TEST_CASE("network-permitted app can reach the host network") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!isolation_available(paths)) {
        MESSAGE("SKIP: bubblewrap isolation unavailable on this host");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);

    install_probe(paths, key, "com.example.net", /*permissions=*/{"network"},
                  "/nonexistent-home-marker", "/nonexistent-other", work);

    TcpListener listener; // host loopback listener, reachable in the shared netns
    util::spit(paths.data_dir() / "com.example.net" / "target",
               std::string_view("127.0.0.1:" + std::to_string(listener.port)));

    run_app(paths, "com.example.net", {});

    const std::string r = read_report(paths, "com.example.net");
    REQUIRE_FALSE(r.empty());
    CHECK(report_has(r, "net:connected")); // network permitted -> reachable
    // The baseline still holds even with network permitted.
    CHECK(report_has(r, "approot:ro"));
    CHECK(report_has(r, "data:writable"));
}

TEST_CASE("FAIL CLOSED: a hidden/broken backend never runs the app directly") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!isolation_available(paths)) {
        MESSAGE("SKIP: bubblewrap isolation unavailable on this host");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    install_probe(paths, key, "com.example.fc", {}, "/x", "/y", work);
    util::spit(paths.data_dir() / "com.example.fc" / "target",
               std::string_view("10.255.255.1:9"));

    // Hide the backend: point LEXE_BWRAP at a path that does not exist.
    util::set_env("LEXE_BWRAP", "/definitely/not/bwrap");
    CHECK_THROWS_AS(run_app(paths, "com.example.fc", {}), lexe::IsolationError);
    util::unset_env("LEXE_BWRAP");

    // The application must NOT have executed — no report was written.
    CHECK(read_report(paths, "com.example.fc").empty());
}

} // TEST_SUITE("isolation_linux")
#endif // _WIN32
