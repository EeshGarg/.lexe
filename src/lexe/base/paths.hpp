#pragma once
// paths — resolves every directory the runtime touches (FORMAT-0.1 §9,
// ARCHITECTURE.md #Modules). Constructed once from the environment; no
// mutable globals. `LEXE_HOME` overrides everything (used by tests).

#include <filesystem>

namespace lexe {

/// Whether the desktop-integration directories below are the ones a desktop
/// environment actually reads.
///
/// This distinction exists because the two things `LEXE_HOME` is used for pull
/// in opposite directions. A desktop only ever reads `$XDG_DATA_HOME`
/// (default `~/.local/share`) — a `.desktop` entry or MIME package written
/// anywhere else is inert. But `LEXE_HOME` is precisely how the test suite and
/// the demos keep their writes out of the developer's real profile, and
/// nothing in the environment distinguishes a test run from a real install
/// under a custom `LEXE_HOME`. Guessing wrong in one direction leaves an inert
/// file; guessing wrong in the other has `./build/lexe_tests` scatter entries
/// through the developer's own `~/.local/share/applications`. So confinement
/// wins whenever `LEXE_HOME` is set, and the runtime reports the scope instead
/// of claiming a registration the desktop cannot see (see
/// desktop::IntegrationResult).
enum class DesktopScope {
    /// `$XDG_DATA_HOME/{applications,icons,mime}` — scanned by the desktop, so
    /// what integration writes there is live.
    xdg,
    /// `<LEXE_HOME>/{applications,icons,mime}` — a private copy that no
    /// desktop environment scans. Integration still writes it (installation
    /// records and `lexe remove` stay honest), but it registers nothing.
    confined,
};

/// Value type holding all resolved base directories.
///
/// Resolution rules (FORMAT-0.1 §9):
///  * `LEXE_HOME` set (non-empty): every directory lives under it —
///    apps/, data/, cache/, applications/, icons/hicolor/, mime/ — and
///    `desktop_scope()` is `confined`.
///  * Linux default: `$XDG_DATA_HOME/lexe` or `~/.local/share/lexe`;
///    cache under `$XDG_CACHE_HOME/lexe` or `~/.cache/lexe`; desktop entries
///    in `$XDG_DATA_HOME/applications`, icons in `$XDG_DATA_HOME/icons/hicolor`,
///    MIME XML in `$XDG_DATA_HOME/mime` — `desktop_scope()` is `xdg`.
///  * Windows (dev host only): `%LOCALAPPDATA%\lexe` with the LEXE_HOME-style
///    sub-layout (desktop integration is a no-op on Windows anyway), so the
///    scope is `confined` there too.
class Paths {
public:
    /// Read the environment and resolve all directories. Throws lexe::Error
    /// when no home base can be determined. Does not create directories.
    static Paths detect();

    /// The Lexe base directory (`<LEXE_HOME>` in FORMAT-0.1 §9).
    const std::filesystem::path& home() const { return home_; }

    /// Installed applications root: `<home>/apps` (FORMAT-0.1 §9).
    std::filesystem::path apps_dir() const { return home_ / "apps"; }
    /// Per-app persistent data root: `<home>/data` (removed only on --purge-data).
    std::filesystem::path data_dir() const { return home_ / "data"; }
    /// Download/scratch cache (update packages land here first).
    const std::filesystem::path& cache_dir() const { return cache_; }
    /// Where `.desktop` entries are written (XDG applications dir).
    const std::filesystem::path& applications_dir() const { return applications_; }
    /// hicolor icon theme root (icons copied here, FORMAT-0.1 §9).
    const std::filesystem::path& icons_dir() const { return icons_; }
    /// XDG MIME package dir (MIME XML for file associations).
    const std::filesystem::path& mime_dir() const { return mime_; }

    // --- Definitive Architecture §9 / §10: state and configuration ---------
    //
    // These are deliberately NOT under the application store. Diagnostics are
    // volatile STATE ($XDG_STATE_HOME) and user overrides are CONFIGURATION
    // ($XDG_CONFIG_HOME); neither belongs to a signed package, and changing
    // them must never touch or invalidate an installed application.

    /// Runtime state root: `$XDG_STATE_HOME/lexe` or `~/.local/state/lexe`.
    const std::filesystem::path& state_dir() const { return state_; }
    /// User configuration root: `$XDG_CONFIG_HOME/lexe` or `~/.config/lexe`.
    const std::filesystem::path& config_dir() const { return config_; }

    /// The freedesktop default-application list (`$XDG_CONFIG_HOME/
    /// mimeapps.list`). Writing the `.lexe` default association HERE — rather
    /// than relying on a session-time association — is what makes the handler
    /// survive logout and reboot (Definitive Architecture §14.1).
    std::filesystem::path mimeapps_file() const {
        return config_home_ / "mimeapps.list";
    }

    /// Structured execution-error records (Definitive Architecture §9):
    /// `<state>/errors/<application-id>/`.
    std::filesystem::path errors_dir() const { return state_ / "errors"; }
    /// Per-application user overrides (§10): `<config>/apps/<id>.json`.
    std::filesystem::path apps_config_dir() const { return config_ / "apps"; }
    /// Generated `.lexe` launch references (§15.1): `<home>/launch/<id>.lexe`.
    std::filesystem::path launch_dir() const { return home_ / "launch"; }
    /// Machine-local key material (the launch-reference signing key, §4
    /// "Locally Trusted"): `<home>/keys`.
    std::filesystem::path keys_dir() const { return home_ / "keys"; }
    /// The durable desktop-integration state file (§15.1 "Durable
    /// integration"): `<home>/integration.json`.
    std::filesystem::path integration_state_file() const {
        return home_ / "integration.json";
    }
    /// Whether `applications_dir()`, `icons_dir()` and `mime_dir()` are the
    /// XDG user directories a desktop reads, or a copy confined under
    /// `LEXE_HOME` that nothing reads. Callers that report what desktop
    /// integration achieved MUST consult this: writing the files always
    /// succeeds, so success alone says nothing about whether the desktop can
    /// see them.
    DesktopScope desktop_scope() const { return desktop_scope_; }

private:
    std::filesystem::path home_;
    std::filesystem::path cache_;
    std::filesystem::path applications_;
    std::filesystem::path icons_;
    std::filesystem::path mime_;
    std::filesystem::path state_;
    std::filesystem::path config_;
    std::filesystem::path config_home_;
    DesktopScope desktop_scope_ = DesktopScope::confined;
};

} // namespace lexe
