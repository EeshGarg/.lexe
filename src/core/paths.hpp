#pragma once
// paths — resolves every directory the runtime touches (FORMAT-0.1 §9,
// ARCHITECTURE.md #Modules). Constructed once from the environment; no
// mutable globals. `LEXE_HOME` overrides everything (used by tests).

#include <filesystem>

namespace lexe {

/// Value type holding all resolved base directories.
///
/// Resolution rules (FORMAT-0.1 §9):
///  * `LEXE_HOME` set (non-empty): every directory lives under it —
///    apps/, data/, cache/, applications/, icons/hicolor/, mime/.
///  * Linux default: `$XDG_DATA_HOME/lexe` or `~/.local/share/lexe`;
///    cache under `$XDG_CACHE_HOME/lexe` or `~/.cache/lexe`; desktop entries
///    in `$XDG_DATA_HOME/applications`, icons in `$XDG_DATA_HOME/icons/hicolor`,
///    MIME XML in `$XDG_DATA_HOME/mime`.
///  * Windows (dev host only): `%LOCALAPPDATA%\lexe` with the LEXE_HOME-style
///    sub-layout (desktop integration is a no-op on Windows anyway).
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

private:
    std::filesystem::path home_;
    std::filesystem::path cache_;
    std::filesystem::path applications_;
    std::filesystem::path icons_;
    std::filesystem::path mime_;
};

} // namespace lexe
