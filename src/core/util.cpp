// util — implementation. See util.hpp.

#include "core/util.hpp"
#include "core/error.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace fs = std::filesystem;

namespace lexe::util {

// ---------------------------------------------------------------- hex

static constexpr char kHexDigits[] = "0123456789abcdef";

std::string hex_encode(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kHexDigits[data[i] >> 4]);
        out.push_back(kHexDigits[data[i] & 0x0f]);
    }
    return out;
}

std::string hex_encode(const std::vector<std::uint8_t>& data) {
    return hex_encode(data.data(), data.size());
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<std::uint8_t> hex_decode(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        throw Error("hex_decode: odd-length input");
    }
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hex_nibble(hex[i]);
        const int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            throw Error("hex_decode: invalid hex digit");
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// ---------------------------------------------------------------- base64

static constexpr char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= len) {
        const std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                                (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                                static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(kB64Alphabet[(v >> 18) & 0x3f]);
        out.push_back(kB64Alphabet[(v >> 12) & 0x3f]);
        out.push_back(kB64Alphabet[(v >> 6) & 0x3f]);
        out.push_back(kB64Alphabet[v & 0x3f]);
        i += 3;
    }
    const std::size_t rem = len - i;
    if (rem == 1) {
        const std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
        out.push_back(kB64Alphabet[(v >> 18) & 0x3f]);
        out.push_back(kB64Alphabet[(v >> 12) & 0x3f]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                                (static_cast<std::uint32_t>(data[i + 1]) << 8);
        out.push_back(kB64Alphabet[(v >> 18) & 0x3f]);
        out.push_back(kB64Alphabet[(v >> 12) & 0x3f]);
        out.push_back(kB64Alphabet[(v >> 6) & 0x3f]);
        out.push_back('=');
    }
    return out;
}

std::string base64_encode(const std::vector<std::uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::vector<std::uint8_t> base64_decode(std::string_view b64) {
    if (b64.empty()) return {};
    if (b64.size() % 4 != 0) {
        throw Error("base64_decode: length not a multiple of 4");
    }
    std::size_t pad = 0;
    if (b64.back() == '=') {
        ++pad;
        if (b64.size() >= 2 && b64[b64.size() - 2] == '=') ++pad;
    }
    std::vector<std::uint8_t> out;
    out.reserve((b64.size() / 4) * 3);
    for (std::size_t i = 0; i < b64.size(); i += 4) {
        int v[4];
        for (std::size_t j = 0; j < 4; ++j) {
            const char c = b64[i + j];
            if (c == '=') {
                // '=' allowed only in the final positions covered by `pad`.
                if (i + j < b64.size() - pad) {
                    throw Error("base64_decode: '=' in the middle of input");
                }
                v[j] = 0;
            } else {
                v[j] = b64_value(c);
                if (v[j] < 0) throw Error("base64_decode: invalid character");
            }
        }
        const std::uint32_t n = (static_cast<std::uint32_t>(v[0]) << 18) |
                                (static_cast<std::uint32_t>(v[1]) << 12) |
                                (static_cast<std::uint32_t>(v[2]) << 6) |
                                static_cast<std::uint32_t>(v[3]);
        out.push_back(static_cast<std::uint8_t>((n >> 16) & 0xff));
        out.push_back(static_cast<std::uint8_t>((n >> 8) & 0xff));
        out.push_back(static_cast<std::uint8_t>(n & 0xff));
    }
    out.resize(out.size() - pad);
    return out;
}

// ---------------------------------------------------------------- file IO

std::vector<std::uint8_t> slurp(const fs::path& file) {
    std::error_code ec;
    if (!fs::exists(file, ec)) {
        throw NotFoundError("file not found: " + file.string());
    }
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        throw Error("cannot open file for reading: " + file.string());
    }
    std::vector<std::uint8_t> data;
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        throw Error("cannot determine file size: " + file.string());
    }
    in.seekg(0, std::ios::beg);
    data.resize(static_cast<std::size_t>(size));
    if (size > 0) {
        in.read(reinterpret_cast<char*>(data.data()), size);
        if (!in) {
            throw Error("read failed: " + file.string());
        }
    }
    return data;
}

std::string slurp_text(const fs::path& file) {
    const auto bytes = slurp(file);
    return std::string(bytes.begin(), bytes.end());
}

void spit(const fs::path& file, const std::uint8_t* data, std::size_t len) {
    if (file.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(file.parent_path(), ec);
        if (ec) {
            throw Error("cannot create directory " + file.parent_path().string() +
                        ": " + ec.message());
        }
    }
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw Error("cannot open file for writing: " + file.string());
    }
    if (len > 0) {
        out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    }
    out.flush();
    if (!out) {
        throw Error("write failed: " + file.string());
    }
}

void spit(const fs::path& file, const std::vector<std::uint8_t>& data) {
    spit(file, data.data(), data.size());
}

void spit(const fs::path& file, std::string_view text) {
    spit(file, reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

// ---------------------------------------------------------------- dir ops

void copy_recursive(const fs::path& from, const fs::path& to) {
    std::error_code ec;
    if (!fs::exists(from, ec)) {
        throw NotFoundError("copy_recursive: source not found: " + from.string());
    }
    if (to.has_parent_path()) {
        fs::create_directories(to.parent_path(), ec);
    }
    fs::copy(from, to,
             fs::copy_options::recursive | fs::copy_options::overwrite_existing |
                 fs::copy_options::copy_symlinks,
             ec);
    if (ec) {
        throw Error("copy_recursive: " + from.string() + " -> " + to.string() +
                    ": " + ec.message());
    }
}

void remove_recursive(const fs::path& p) {
    std::error_code ec;
    fs::remove_all(p, ec);
    if (ec && fs::exists(p)) {
        throw Error("remove_recursive: " + p.string() + ": " + ec.message());
    }
}

// ---------------------------------------------------------------- env

#ifdef _WIN32

static std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                        static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) throw Error("invalid UTF-8 string");
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                          w.data(), n);
    return w;
}

static std::string narrow(const wchar_t* s, std::size_t len) {
    if (len == 0) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, s, static_cast<int>(len),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0) throw Error("invalid UTF-16 string");
    std::string out(static_cast<std::size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s, static_cast<int>(len), out.data(), n,
                          nullptr, nullptr);
    return out;
}

std::optional<std::string> get_env(const std::string& name) {
    const std::wstring wname = widen(name);
    DWORD n = ::GetEnvironmentVariableW(wname.c_str(), nullptr, 0);
    if (n == 0) return std::nullopt;
    std::wstring value(n, L'\0');
    n = ::GetEnvironmentVariableW(wname.c_str(), value.data(), n);
    if (n == 0) return std::nullopt;
    return narrow(value.data(), n);
}

void set_env(const std::string& name, const std::string& value) {
    const std::wstring wname = widen(name);
    const std::wstring wvalue = widen(value);
    if (!::SetEnvironmentVariableW(wname.c_str(), wvalue.c_str())) {
        throw Error("set_env failed: " + name);
    }
    ::_wputenv_s(wname.c_str(), wvalue.c_str()); // keep the CRT copy in sync
}

void unset_env(const std::string& name) {
    const std::wstring wname = widen(name);
    ::SetEnvironmentVariableW(wname.c_str(), nullptr);
    ::_wputenv_s(wname.c_str(), L"");
}

#else // POSIX

std::optional<std::string> get_env(const std::string& name) {
    const char* v = std::getenv(name.c_str());
    if (v == nullptr) return std::nullopt;
    return std::string(v);
}

void set_env(const std::string& name, const std::string& value) {
    if (::setenv(name.c_str(), value.c_str(), 1) != 0) {
        throw Error("set_env failed: " + name);
    }
}

void unset_env(const std::string& name) {
    ::unsetenv(name.c_str());
}

#endif

// ---------------------------------------------------------------- processes

#ifdef _WIN32

// Quote one argument per the CommandLineToArgvW / MSVC CRT rules so the child
// parses back exactly the argv we were given. No shell is involved.
static std::wstring quote_windows_arg(const std::wstring& arg) {
    if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return arg;
    }
    std::wstring out;
    out.push_back(L'"');
    std::size_t i = 0;
    while (i < arg.size()) {
        std::size_t backslashes = 0;
        while (i < arg.size() && arg[i] == L'\\') {
            ++backslashes;
            ++i;
        }
        if (i == arg.size()) {
            // Trailing backslashes: double them so the closing quote survives.
            out.append(backslashes * 2, L'\\');
            break;
        }
        if (arg[i] == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
        } else {
            out.append(backslashes, L'\\');
            out.push_back(arg[i]);
        }
        ++i;
    }
    out.push_back(L'"');
    return out;
}

ProcessResult run_process(const std::vector<std::string>& argv, const RunOptions& opts) {
    if (argv.empty()) throw Error("run_process: empty argv");

    std::wstring cmdline;
    for (std::size_t i = 0; i < argv.size(); ++i) {
        if (i > 0) cmdline.push_back(L' ');
        cmdline += quote_windows_arg(widen(argv[i]));
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    if (opts.capture_stdout) {
        if (!::CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
            throw Error("run_process: CreatePipe failed");
        }
        ::SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = write_pipe;
        si.hStdError = ::GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    }

    std::wstring wcwd;
    if (opts.cwd.has_value()) wcwd = opts.cwd->wstring();

    PROCESS_INFORMATION pi{};
    std::wstring mutable_cmdline = cmdline; // CreateProcessW may modify it
    const BOOL ok = ::CreateProcessW(
        nullptr, mutable_cmdline.data(), nullptr, nullptr,
        opts.capture_stdout ? TRUE : FALSE, 0, nullptr,
        opts.cwd.has_value() ? wcwd.c_str() : nullptr, &si, &pi);
    if (opts.capture_stdout) ::CloseHandle(write_pipe);
    if (!ok) {
        if (opts.capture_stdout) ::CloseHandle(read_pipe);
        throw Error("run_process: cannot start process: " + argv[0]);
    }

    std::string output;
    if (opts.capture_stdout) {
        char buf[4096];
        DWORD n = 0;
        while (::ReadFile(read_pipe, buf, sizeof(buf), &n, nullptr) && n > 0) {
            output.append(buf, n);
        }
        ::CloseHandle(read_pipe);
    }

    ::WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    ::GetExitCodeProcess(pi.hProcess, &code);
    ::CloseHandle(pi.hProcess);
    ::CloseHandle(pi.hThread);

    return ProcessResult{static_cast<int>(code), std::move(output)};
}

#else // POSIX

ProcessResult run_process(const std::vector<std::string>& argv, const RunOptions& opts) {
    if (argv.empty()) throw Error("run_process: empty argv");

    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);

    int pipefd[2] = {-1, -1};
    if (opts.capture_stdout && ::pipe(pipefd) != 0) {
        throw Error("run_process: pipe() failed");
    }

    posix_spawn_file_actions_t fa;
    ::posix_spawn_file_actions_init(&fa);
    if (opts.capture_stdout) {
        ::posix_spawn_file_actions_addclose(&fa, pipefd[0]);
        ::posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO);
        ::posix_spawn_file_actions_addclose(&fa, pipefd[1]);
    }
    std::string cwd_str;
    if (opts.cwd.has_value()) {
        cwd_str = opts.cwd->string();
        ::posix_spawn_file_actions_addchdir_np(&fa, cwd_str.c_str());
    }

    pid_t pid = -1;
    const int err = ::posix_spawnp(&pid, cargv[0], &fa, nullptr, cargv.data(), environ);
    ::posix_spawn_file_actions_destroy(&fa);
    if (opts.capture_stdout) ::close(pipefd[1]);
    if (err != 0) {
        if (opts.capture_stdout) ::close(pipefd[0]);
        throw Error("run_process: cannot start process: " + argv[0] + ": " +
                    std::strerror(err));
    }

    std::string output;
    if (opts.capture_stdout) {
        char buf[4096];
        ssize_t n = 0;
        while ((n = ::read(pipefd[0], buf, sizeof(buf))) > 0) {
            output.append(buf, static_cast<std::size_t>(n));
        }
        ::close(pipefd[0]);
    }

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        throw Error("run_process: waitpid failed");
    }
    int code = 1;
    if (WIFEXITED(status)) {
        code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        code = 128 + WTERMSIG(status);
    }
    return ProcessResult{code, std::move(output)};
}

#endif

// ---------------------------------------------------------------- time

std::string now_utc_string() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    ::gmtime_s(&tm, &t);
#else
    ::gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                  tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

} // namespace lexe::util
