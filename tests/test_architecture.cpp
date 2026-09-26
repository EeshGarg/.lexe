// Architecture tests — the dependency rules of docs/ARCHITECTURE.md, enforced.
//
// Two claims are made in prose there, and prose rots. Both are checked here
// against the actual source tree, so a violation fails the test run instead of
// quietly becoming true:
//
//   1. `src/lexe/` is layered. Each subsystem may include only subsystems
//      BELOW it in the documented order, and `base/` includes nothing of ours.
//      This is what makes "one engine" a structure rather than a directory
//      name: a cycle between subsystems means there is no single direction of
//      dependency left to reason about.
//
//   2. The frontends under `src/gui/` reach the engine only through its
//      headers, and the engine never reaches back into a frontend.
//
// The scan is textual on purpose: it reads what the preprocessor would see
// rather than what a build happens to link, so a violation is caught even in a
// file no configuration compiles on this host.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/util.hpp"

#include <algorithm>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// The documented order. Index = layer; a subsystem may include only strictly
// lower indices. Keep this identical to the subsystem table in
// docs/ARCHITECTURE.md — the two are meant to be read together.
const std::vector<std::string>& layer_order() {
    static const std::vector<std::string> order = {
        "base",        "package", "analysis",    "sandbox", "state",
        "verify",      "diagnostics",
        "runtime",     "integration", "install", "commands",
    };
    return order;
}

int layer_of(const std::string& subsystem) {
    const auto& order = layer_order();
    const auto it = std::find(order.begin(), order.end(), subsystem);
    if (it == order.end()) return -1;
    return static_cast<int>(std::distance(order.begin(), it));
}

fs::path source_root() { return fs::path(LEXE_SOURCE_DIR) / "src"; }

std::vector<fs::path> sources_under(const fs::path& root) {
    std::vector<fs::path> files;
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return files;
    for (fs::recursive_directory_iterator it(root, ec), end; it != end;
         it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file()) continue;
        const std::string ext = it->path().extension().string();
        if (ext == ".cpp" || ext == ".hpp") files.push_back(it->path());
    }
    std::sort(files.begin(), files.end());
    return files;
}

// Every `#include "..."` target in `file`, as written.
std::vector<std::string> quoted_includes(const fs::path& file) {
    const std::string text = lexe::util::slurp_text(file);
    std::vector<std::string> out;
    const std::string needle = "#include \"";
    std::size_t pos = 0;
    while ((pos = text.find(needle, pos)) != std::string::npos) {
        const std::size_t start = pos + needle.size();
        const std::size_t end = text.find('"', start);
        if (end == std::string::npos) break;
        out.push_back(text.substr(start, end - start));
        pos = end;
    }
    return out;
}

std::string bullets(const std::vector<std::string>& lines) {
    std::string s;
    for (const std::string& line : lines) s += "  " + line + "\n";
    return s;
}

// The subsystem directory an engine include names, or "" if it names none.
std::string included_subsystem(const std::string& include) {
    if (include.rfind("lexe/", 0) != 0) return "";
    const std::size_t slash = include.find('/', 5);
    if (slash == std::string::npos) return "";
    return include.substr(5, slash - 5);
}

} // namespace

TEST_SUITE("architecture") {

TEST_CASE("every engine subsystem on disk is a documented layer") {
    std::set<std::string> found;
    std::error_code ec;
    for (const auto& entry :
         fs::directory_iterator(source_root() / "lexe", ec)) {
        if (entry.is_directory()) found.insert(entry.path().filename().string());
    }
    REQUIRE_FALSE(found.empty());
    for (const std::string& subsystem : found) {
        INFO("src/lexe/" << subsystem
                         << " is not in the documented layer order — add it to "
                            "docs/ARCHITECTURE.md and to layer_order()");
        CHECK(layer_of(subsystem) >= 0);
    }
    // And the reverse: the documented order must not name a layer that is gone.
    for (const std::string& subsystem : layer_order()) {
        INFO("docs/ARCHITECTURE.md names src/lexe/"
             << subsystem << ", which does not exist on disk");
        CHECK(found.count(subsystem) == 1);
    }
}

TEST_CASE("the engine is layered: no subsystem includes one above it") {
    std::vector<std::string> violations;
    for (const fs::path& file : sources_under(source_root() / "lexe")) {
        const std::string mine = file.parent_path().filename().string();
        const int my_layer = layer_of(mine);
        if (my_layer < 0) continue; // reported by the test above
        for (const std::string& inc : quoted_includes(file)) {
            const std::string target = included_subsystem(inc);
            const int target_layer = target.empty() ? -1 : layer_of(target);
            if (target_layer > my_layer) {
                violations.push_back(file.filename().string() + " (" + mine +
                                     ") includes " + inc);
            }
        }
    }
    INFO("upward includes break the one-way dependency direction:\n"
         << bullets(violations));
    CHECK(violations.empty());
}

TEST_CASE("base/ depends on no other engine subsystem") {
    // Stated separately because it is the claim most worth keeping true: the
    // foundations must stay usable without dragging installed state in.
    std::vector<std::string> violations;
    for (const fs::path& file :
         sources_under(source_root() / "lexe" / "base")) {
        for (const std::string& inc : quoted_includes(file)) {
            if (inc.rfind("lexe/base/", 0) == 0) continue;
            if (inc.rfind("lexe/", 0) == 0) {
                violations.push_back(file.filename().string() + " includes " +
                                     inc);
            }
        }
    }
    INFO("base/ reached upward:\n" << bullets(violations));
    CHECK(violations.empty());
}

TEST_CASE("the engine never includes a frontend") {
    std::vector<std::string> violations;
    for (const fs::path& file : sources_under(source_root() / "lexe")) {
        for (const std::string& inc : quoted_includes(file)) {
            if (inc.rfind("gui/", 0) == 0) {
                violations.push_back(file.filename().string() + " includes " +
                                     inc);
            }
        }
    }
    INFO("the dependency direction is engine -> frontends, never the reverse:\n"
         << bullets(violations));
    CHECK(violations.empty());
}

TEST_CASE("each frontend reaches the engine only through headers") {
    // A frontend including another frontend's translation unit is how the two
    // consumer GUIs came to share one view model by including a .cpp that owns
    // a main(). Shared presentation logic belongs in a header both include.
    std::vector<std::string> violations;
    for (const fs::path& file : sources_under(source_root() / "gui")) {
        for (const std::string& inc : quoted_includes(file)) {
            const bool engine_header = inc.rfind("lexe/", 0) == 0;
            const bool gui_header = inc.rfind("gui/", 0) == 0 &&
                                    fs::path(inc).extension() == ".hpp";
            if (!engine_header && !gui_header) {
                violations.push_back(file.filename().string() + " includes " +
                                     inc);
            }
        }
    }
    INFO("a frontend may include engine headers and gui/*.hpp, nothing else:\n"
         << bullets(violations));
    CHECK(violations.empty());
}

} // TEST_SUITE
