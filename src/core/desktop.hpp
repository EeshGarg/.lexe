#pragma once
// desktop — the `.desktop` and shared-mime-info DOCUMENTS an installed
// application is registered with (FORMAT-0.1 §9, SPEC "Installed Application
// Representation"). Pure content generation only: every string here is a
// function of the manifest, computed identically on every platform and
// testable as a string anywhere.
//
// WRITING these documents, registering them, recording them in
// `integration.json` and repairing them is `DesktopIntegration`
// (core/integration.hpp) and belongs to it alone. This module used to own a
// second copy of that machinery — it planned files, wrote them, refreshed the
// freedesktop databases, and registered the runtime handler under a MIME type
// (`application/x-lexe`) that is no longer the one the runtime claims. Two
// engines for one job is how the alpha ended up with registrations that
// depended on which implementation ran last. There is one now.

#include "core/manifest.hpp"

#include <string>

namespace lexe::desktop {

/// The `.desktop` entry contents for an installed app. The Exec line is
/// always `lexe run <id>` — the stable Lexe launcher, never a
/// version-specific path (SPEC "Installed Application Representation").
/// Values are escaped per the Desktop Entry specification.
std::string desktop_entry_text(const Manifest& manifest);

/// shared-mime-info XML for the manifest's `integration.fileAssociations`:
/// one <mime-type> per distinct mimeType, one <glob> per extension.
/// XML-special characters in names/types/patterns are escaped.
std::string mime_xml_text(const Manifest& manifest);

} // namespace lexe::desktop
