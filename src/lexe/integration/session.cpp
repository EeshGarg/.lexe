// session — systemd `--user` unit generation (session.hpp, docs/SERVICES.md).

#include "lexe/integration/session.hpp"

#include "lexe/base/error.hpp"

#include <string>

namespace lexe::session {

namespace {

/// Strip what would end a unit directive early.
///
/// The `.service` format is INI-like: a value runs to end of line. A newline
/// inside one would close the directive and let whatever follows become a NEW
/// one — and `Description=` is derived from `manifest.name`, which is
/// publisher-controlled text, so a name containing a newline could otherwise
/// inject `ExecStart=`. Exactly the desktop-entry injection hazard in a
/// different file format, and it gets the same treatment: the metacharacter is
/// removed rather than trusted.
///
/// Stripped rather than rejected because a name is display text and a package
/// with an odd one is not necessarily hostile. `systemd-escape` semantics are
/// not used: those are for unit NAMES, and these are values.
std::string strip_control(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (const unsigned char c : text) {
        // A newline or carriage return ends the directive; a NUL ends the file
        // as far as the parser is concerned. None can survive.
        if (c == '\n' || c == '\r' || c == '\0') {
            out += ' ';
            continue;
        }
        // Other control characters have no meaning in a value and no business
        // in a description.
        if (c < 0x20 || c == 0x7F) continue;
        out += static_cast<char>(c);
    }
    return out;
}

/// Escape systemd's SPECIFIERS in any value.
///
/// `%` introduces a specifier that systemd expands — `%h` becomes the home
/// directory, `%i` the instance name, and an unknown one is an error that makes
/// the whole unit fail to load. `%` is a legal character in a POSIX path, so a
/// runtime installed under `~/opt/50%off/` would otherwise produce a unit that
/// either points somewhere else entirely or refuses to load at all. `%%` is the
/// literal.
std::string escape_specifiers(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text) {
        if (c == '%') out += '%';
        out += c;
    }
    return out;
}

/// A value for a directive that takes the rest of the line verbatim, such as
/// `Description=`.
std::string unit_value(const std::string& text) {
    return escape_specifiers(strip_control(text));
}

/// One word of a command line, quoted so that systemd passes it through whole.
///
/// This exists because of a defect this code had and a test now pins: systemd
/// splits `ExecStart=` on WHITESPACE, exactly as a shell would, and the runtime
/// path is wherever the runtime happens to be installed. A `lexe` under
/// `/mnt/c/Users/Some Name/build/lexe` produced
///
///     ExecStart=/mnt/c/Users/Some Name/build/lexe run <id> --wait
///
/// which systemd read as the command `/mnt/c/Users/Some` with the arguments
/// `Name/build/lexe`, `run`, ... and failed with status 203/EXEC at every start
/// and every restart. The unit was valid, enabled, and could never run.
///
/// So every word is double-quoted, and the three characters that mean something
/// inside systemd's double quotes are escaped:
///
///   `\` and `"`   C-style escapes within the quoted word
///   `$`            variable expansion; `$$` is the literal dollar
///   `%`            a specifier, handled by escape_specifiers above
///
/// Quoting unconditionally rather than only when a space is present: a rule with
/// no exceptions cannot be got wrong by the next path that turns up, and systemd
/// accepts a quoted word that needed no quoting.
std::string unit_exec_word(const std::string& text) {
    const std::string clean = strip_control(text);
    std::string out = "\"";
    for (const char c : clean) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '$': out += "$$"; break;
        case '%': out += "%%"; break;
        default: out += c;
        }
    }
    out += '"';
    return out;
}

/// `NAME=value` for `Environment=`, quoted as one assignment.
///
/// Same whitespace hazard as a command line, for the same reason: systemd splits
/// `Environment=` into space-separated assignments, so an unquoted
/// `LEXE_HOME=/tmp/a b/home` sets `LEXE_HOME=/tmp/a` and then fails on the word
/// `b/home`, which is not an assignment. Under a scratch root with a space this
/// silently pointed the service at the wrong installation.
std::string unit_env_assignment(const std::string& name,
                                const std::string& value) {
    const std::string clean = strip_control(value);
    std::string out = "\"" + name + "=";
    for (const char c : clean) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '%': out += "%%"; break;
        default: out += c;
        }
    }
    out += '"';
    return out;
}

} // namespace

bool is_session_manageable(const Manifest& manifest) {
    return manifest.role == PackageRole::Application &&
           manifest.launch_mode == LaunchMode::Service;
}

std::string session_unmanageable_reason(const Manifest& manifest) {
    if (is_session_manageable(manifest)) return {};
    if (manifest.role != PackageRole::Application) {
        return "A launch reference is not an application; there is no lifetime "
               "for a service manager to own.";
    }
    switch (manifest.launch_mode) {
    case LaunchMode::Gui:
        return "This is a desktop application, not a service. A service manager "
               "that restarted it when it exited would be overruling the person "
               "who closed its window.";
    case LaunchMode::Console:
        return "This is a command-line program, not a service. It runs when you "
               "run it and finishes; there is no lifetime to supervise.";
    case LaunchMode::Service:
    default:
        return {};
    }
}

std::string unit_name(const std::string& app_id) {
    return "lexe-" + app_id + ".service";
}

std::string unit_path(const Paths& paths, const std::string& app_id) {
    return (paths.systemd_user_dir() / unit_name(app_id)).generic_string();
}

std::string unit_text(const UnitInputs& inputs) {
    if (!is_session_manageable(inputs.manifest)) {
        throw Error("session: " + inputs.manifest.id +
                        " does not declare launch.mode \"service\"; a unit for it "
                        "would supervise a lifetime it does not have",
                    session_unmanageable_reason(inputs.manifest));
    }
    if (inputs.runtime_path.empty()) {
        throw Error("session: the path of the lexe runtime is required to "
                    "generate a unit",
                    "A systemd --user unit does not inherit PATH, so ExecStart "
                    "must name the runtime absolutely.");
    }

    const std::string display = unit_value(
        inputs.manifest.name.empty() ? inputs.manifest.id : inputs.manifest.name);

    std::string unit;
    unit += "# Generated by .LEXE. Do not edit.\n";
    unit += "#\n";
    unit += "# `lexe doctor` records this file's content hash and will report it "
            "as modified\n";
    unit += "# if it changes; `lexe doctor --repair` rewrites it. Change the "
            "application,\n";
    unit += "# not the unit. Remove it with `lexe service disable " +
            inputs.manifest.id + "`.\n";
    unit += "\n";

    unit += "[Unit]\n";
    unit += "Description=" + display + " (.LEXE)\n";
    unit += "Documentation=man:lexe(1)\n";
    // Bound to the graphical session rather than to default.target alone: a
    // user service whose application is part of someone's desktop should go away
    // with that desktop. PartOf propagates stop/restart, not start.
    unit += "PartOf=graphical-session.target\n";
    unit += "\n";

    unit += "[Service]\n";
    // simple, not forking: the runtime writes no pid file and records no
    // supervisor identity anywhere, so there is nothing for PIDFile= to name.
    unit += "Type=simple\n";
    // --wait is load-bearing. See session.hpp: without it `lexe run` returns
    // immediately for a service, systemd concludes the service died, and
    // Restart= turns that into an infinite restart loop against a payload that
    // is still running.
    unit += "ExecStart=" + unit_exec_word(inputs.runtime_path) + " run " +
            unit_exec_word(inputs.manifest.id) + " --wait\n";
    // on-failure, not always: an application that exits 0 has finished, and
    // restarting it anyway would overrule the program.
    unit += "Restart=on-failure\n";
    unit += "RestartSec=5s\n";
    // Long enough for a sandboxed application to shut down, short enough that a
    // wedged one does not hold up logout indefinitely.
    unit += "TimeoutStopSec=20s\n";
    if (!inputs.lexe_home.empty()) {
        // Only when the installation root is an override. A unit is generated
        // against the root it was enabled from, and pinning it unconditionally
        // would break a home directory that moves.
        unit += "Environment=" +
                unit_env_assignment("LEXE_HOME", inputs.lexe_home) + "\n";
    }
    unit += "\n";

    unit += "[Install]\n";
    unit += "WantedBy=default.target\n";
    return unit;
}

} // namespace lexe::session
