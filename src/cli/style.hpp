#pragma once
// style — tiny, dependency-free terminal styling for the CLI (DX6). Colour is
// applied ONLY when the target stream is an interactive terminal, `NO_COLOR` is
// unset, and `TERM` is not "dumb". Captured output (tests, pipes, `--json`) is
// therefore always plain text, byte-for-byte stable.

#include "core/util.hpp"

#include <string>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace lexe::cli::style {

/// Whether ANSI styling should be emitted for file descriptor `fd` (1=stdout,
/// 2=stderr). Honours NO_COLOR (https://no-color.org) and a "dumb" TERM.
inline bool color_for(int fd) {
    if (util::get_env("NO_COLOR").has_value()) return false;
    if (const auto term = util::get_env("TERM"); term && *term == "dumb") {
        return false;
    }
#if defined(_WIN32)
    return _isatty(fd) != 0;
#else
    return ::isatty(fd) != 0;
#endif
}

/// On Windows, enable ANSI escape processing so styled output renders instead of
/// printing raw escapes. A no-op elsewhere; safe to call once at startup.
inline void enable_ansi_passthrough() {
#if defined(_WIN32)
    for (DWORD handle : {STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
        HANDLE h = GetStdHandle(handle);
        DWORD mode = 0;
        if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
#endif
}

/// Wrap `s` in the SGR sequence `sgr` when `on`; otherwise return it unchanged.
inline std::string paint(bool on, const char* sgr, const std::string& s) {
    if (!on) return s;
    return std::string("\033[").append(sgr).append("m").append(s).append(
        "\033[0m");
}

// Semantic helpers, parameterised by whether the destination stream is styled.
inline std::string bold(bool on, const std::string& s) { return paint(on, "1", s); }
inline std::string dim(bool on, const std::string& s) { return paint(on, "2", s); }
inline std::string red(bool on, const std::string& s) { return paint(on, "31", s); }
inline std::string green(bool on, const std::string& s) { return paint(on, "32", s); }
inline std::string yellow(bool on, const std::string& s) { return paint(on, "33", s); }
inline std::string cyan(bool on, const std::string& s) { return paint(on, "36", s); }

} // namespace lexe::cli::style
