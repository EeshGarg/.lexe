// lexe CLI entry point (ARCHITECTURE.md #CLI). Catches lexe exceptions at
// the top level and maps them to the documented exit codes:
// 0 ok, 1 runtime error, 2 usage, 3 verification failure, 4 not found,
// 5 permission/consent, 6 busy, 7 local trust.

#include "commands.hpp"
#include "style.hpp"

#include "core/error.hpp"

#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace {

// A short, actionable next step for a failure — the "how to fix it" half of a
// good consumer error. Empty when the message already says everything (usage).
std::string hint_for(const std::exception& e) {
    using namespace lexe;
    // A hint the throw site attached always wins: it knows the specific reason,
    // where the type-based fallbacks below only know the category.
    if (const auto* err = dynamic_cast<const Error*>(&e);
        err != nullptr && !err->hint().empty()) {
        return err->hint();
    }
    if (dynamic_cast<const UsageError*>(&e) != nullptr) return "";
    if (dynamic_cast<const ChangedKeyError*>(&e) != nullptr)
        return "The publisher's signing key changed since you installed this. "
               "Inspect it with `lexe trust show <id>`.";
    if (dynamic_cast<const BlockedKeyError*>(&e) != nullptr)
        return "This application is blocked locally. Unblock it with "
               "`lexe trust unblock <id>` if you trust it.";
    if (dynamic_cast<const TrustError*>(&e) != nullptr)
        return "Review the local trust record with `lexe trust show <id>`.";
    if (dynamic_cast<const PermissionError*>(&e) != nullptr)
        return "Review the requested permissions, then re-run with "
               "--accept-permissions to approve them.";
    if (dynamic_cast<const BusyError*>(&e) != nullptr)
        return "Another lexe operation is running for this application. Wait for "
               "it to finish, then retry.";
    if (dynamic_cast<const VerificationError*>(&e) != nullptr)
        return "The package did not verify and was not trusted. Re-download it "
               "from the original source and try again.";
    if (dynamic_cast<const NotFoundError*>(&e) != nullptr)
        return "Check the path, or run `lexe apps` to see installed applications.";
    return "";
}

} // namespace

int main(int argc, char** argv) {
    lexe::cli::style::enable_ansi_passthrough();
    const bool color = lexe::cli::style::color_for(2);

    std::vector<std::string> args;
    args.reserve(argc > 0 ? static_cast<std::size_t>(argc - 1) : 0);
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    try {
        return lexe::cli::dispatch(args);
    } catch (const std::exception& e) {
        namespace s = lexe::cli::style;
        std::cerr << s::red(color, s::bold(color, "lexe:")) << " " << e.what()
                  << "\n";
        if (const std::string hint = hint_for(e); !hint.empty()) {
            std::cerr << s::dim(color, "  hint:") << " " << hint << "\n";
        }
        return lexe::exit_code_for(e);
    }
}
