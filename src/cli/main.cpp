// lexe CLI entry point (ARCHITECTURE.md #CLI). Catches lexe exceptions at
// the top level and maps them to the documented exit codes:
// 0 ok, 1 runtime error, 2 usage, 3 verification failure, 4 not found.

#include "commands.hpp"

#include "core/error.hpp"

#include <exception>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    std::vector<std::string> args;
    args.reserve(argc > 0 ? static_cast<std::size_t>(argc - 1) : 0);
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    try {
        return lexe::cli::dispatch(args);
    } catch (const std::exception& e) {
        std::cerr << "lexe: " << e.what() << "\n";
        return lexe::exit_code_for(e);
    }
}
