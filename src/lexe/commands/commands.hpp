#pragma once
// commands — CLI command dispatch (ARCHITECTURE.md #CLI). main() collects
// argv into UTF-8 strings and calls dispatch(); errors propagate as lexe
// exceptions and are mapped to exit codes in main.cpp via exit_code_for().

#include <string>
#include <vector>

namespace lexe::cli {

/// Dispatch `args` (argv without the program name) to the matching command
/// implementation and return the process exit code. Throws UsageError for
/// unknown/malformed invocations, other lexe errors for failures.
int dispatch(const std::vector<std::string>& args);

/// Usage synopsis (multi-line, one entry per command) printed by `lexe`
/// with no arguments (via UsageError, exit 2) and by `lexe help` (exit 0).
std::string usage_text();

} // namespace lexe::cli
