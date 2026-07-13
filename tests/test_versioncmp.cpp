// versioncmp module tests (ARCHITECTURE.md #Tests): FORMAT-0.1 §8 ordering
// table — numeric vs lexicographic components, the strict-prefix rule, exact
// -1/0/1 results, antisymmetry, and the strictly-greater updater use (§7.7).
// Every test case constructs lexe::test::TempLexeHome first.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/versioncmp.hpp"

#include <string_view>

TEST_SUITE("versioncmp") {

TEST_CASE("ordering table (FORMAT-0.1 §8)") {
    lexe::test::TempLexeHome home;

    struct Row {
        const char* a;
        const char* b;
        int expected; // compare_versions(a, b)
    };
    // Rows with expected -1 are written a < b for readability.
    static constexpr Row rows[] = {
        // --- equality ---
        {"1.0.0", "1.0.0", 0},
        {"0.1", "0.1", 0},
        {"1", "1", 0},
        {"1.4.2", "1.4.2", 0},
        {"1.alpha", "1.alpha", 0},
        // numeric components ignore leading zeros
        {"1.01.0", "1.1.0", 0},
        {"007", "7", 0},
        {"1.0", "1.00", 0},

        // --- numeric comparison when BOTH components are all digits ---
        {"1.2", "1.10", -1},  // lexicographic would say "10" < "2"
        {"1.9", "1.10", -1},
        {"2", "10", -1},
        {"0.9.9", "0.10.0", -1},
        {"1.0.2", "1.0.10", -1},
        {"4.9", "10.0", -1},
        {"1.09", "1.10", -1}, // leading zero still numeric
        // arbitrarily long digit strings (beyond 64-bit range)
        {"18446744073709551615", "18446744073709551616", -1},
        {"1.99999999999999999999", "1.100000000000000000000", -1},

        // --- strict prefix (fewer components) is smaller ---
        {"1.0", "1.0.0", -1},
        {"1", "1.0", -1},
        {"1.4", "1.4.2", -1},
        {"1", "1.0.0.0", -1},
        {"1.01", "1.1.0", -1}, // equal numeric prefix, then shorter

        // --- byte-string comparison when either side is non-numeric ---
        {"1.a", "1.b", -1},
        {"1.alpha", "1.beta", -1},
        {"1.2", "1.2a", -1},   // "2" is a byte-prefix of "2a"
        {"1.10a", "1.9", -1},  // mixed: '1' (0x31) < '9' (0x39) bytewise
        {"1.A", "1.a", -1},    // bytes: 'A' (0x41) < 'a' (0x61)
        {"1.0", "1.0-beta", -1}, // semver-lite: no pre-release semantics
        {"1.0.beta", "1.0.beta.2", -1},
        {"1.0.9z", "1.0.a", -1}, // '9' (0x39) < 'a' (0x61)

        // --- the updater's strictly-greater checks (FORMAT-0.1 §7.7) ---
        {"1.4.2", "1.4.3", -1},
        {"1.4.3", "1.5.0", -1},
        {"0.9", "1.0", -1},
        {"1.9.9", "2.0.0", -1},
    };

    for (const Row& r : rows) {
        CAPTURE(r.a);
        CAPTURE(r.b);
        CHECK(lexe::compare_versions(r.a, r.b) == r.expected);
        // Antisymmetry: swapping the arguments flips the sign.
        CHECK(lexe::compare_versions(r.b, r.a) == -r.expected);
    }
}

TEST_CASE("compare_versions returns exactly -1, 0, or 1") {
    lexe::test::TempLexeHome home;

    CHECK(lexe::compare_versions("1.2", "1.10") == -1);
    CHECK(lexe::compare_versions("1.10", "1.2") == 1);
    CHECK(lexe::compare_versions("3.3", "3.3") == 0);
    CHECK(lexe::compare_versions("zzz", "aaa") == 1);
    CHECK(lexe::compare_versions("1.0.0", "1.0") == 1);
}

TEST_CASE("version_less agrees with compare_versions") {
    lexe::test::TempLexeHome home;

    CHECK(lexe::version_less("1.0.0", "1.0.1"));
    CHECK_FALSE(lexe::version_less("1.0.1", "1.0.0"));
    CHECK_FALSE(lexe::version_less("1.0.0", "1.0.0")); // strictness
    CHECK(lexe::version_less("1.4.2", "1.4.3"));       // update allowed
    CHECK_FALSE(lexe::version_less("1.4.3", "1.4.2")); // downgrade refused
    CHECK_FALSE(lexe::version_less("1.1", "1.01"));    // numerically equal
}

TEST_CASE("degenerate inputs remain totally ordered") {
    lexe::test::TempLexeHome home;

    // Split-on-dot semantics: "" is one empty component, "1." is ["1", ""].
    CHECK(lexe::compare_versions("", "") == 0);
    CHECK(lexe::compare_versions("", "1") == -1);
    CHECK(lexe::compare_versions("1", "") == 1);
    CHECK(lexe::compare_versions("1.", "1") == 1); // ["1",""] vs ["1"]: prefix
    CHECK(lexe::compare_versions("1.", "1.") == 0);
    CHECK(lexe::compare_versions("1..2", "1..2") == 0);
    CHECK(lexe::compare_versions("1..2", "1.0.2") == -1); // "" < "0" bytewise

    // Transitivity spot checks.
    CHECK(lexe::version_less("1.0", "1.0.0"));
    CHECK(lexe::version_less("1.0.0", "1.0.1"));
    CHECK(lexe::version_less("1.0", "1.0.1"));

    // Mixed components use byte order even next to numeric-looking values:
    // "2a" vs "10" compares bytewise ('2' > '1'), so 1.2a > 1.10.
    CHECK(lexe::version_less("1.2", "1.2a"));
    CHECK(lexe::compare_versions("1.2a", "1.10") == 1);
}

} // TEST_SUITE("versioncmp")
