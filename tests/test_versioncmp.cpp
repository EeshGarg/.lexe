// versioncmp module tests (ARCHITECTURE.md #Tests): FORMAT-0.1 §8 ordering
// table — numeric vs lexicographic components, the strict-prefix rule, exact
// -1/0/1 results, antisymmetry, and the strictly-greater updater use (§7.7).
// Every test case constructs lexe::test::TempLexeHome first.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/versioncmp.hpp"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

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
        {"1.2", "1.2a", -1},   // mixed class: numeric "2" < non-numeric "2a"
        {"1.9", "1.10a", -1},  // mixed class: numeric "9" < non-numeric "10a"
        {"1.A", "1.a", -1},    // both non-numeric, bytes: 'A' (0x41) < 'a'
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
    // The empty component is non-numeric, so a numeric neighbour sorts before
    // it (the class-partition rule that keeps the order total — FORMAT-0.1 §8).
    CHECK(lexe::compare_versions("", "") == 0);
    CHECK(lexe::compare_versions("", "1") == 1);  // numeric "1" precedes empty
    CHECK(lexe::compare_versions("1", "") == -1);
    CHECK(lexe::compare_versions("1.", "1") == 1); // ["1",""] vs ["1"]: prefix
    CHECK(lexe::compare_versions("1.", "1.") == 0);
    CHECK(lexe::compare_versions("1..2", "1..2") == 0);
    CHECK(lexe::compare_versions("1..2", "1.0.2") == 1); // "" follows numeric "0"

    // Transitivity spot checks.
    CHECK(lexe::version_less("1.0", "1.0.0"));
    CHECK(lexe::version_less("1.0.0", "1.0.1"));
    CHECK(lexe::version_less("1.0", "1.0.1"));

    // Mixed components partition by class: a numeric component sorts before a
    // non-numeric one, so 1.2 < 1.2a and 1.2a > 1.10 (non-numeric "2a" after
    // numeric "10").
    CHECK(lexe::version_less("1.2", "1.2a"));
    CHECK(lexe::compare_versions("1.2a", "1.10") == 1);
}

// Regression for the review finding: version_less must be a valid strict-weak
// ordering, or feeding it to std::sort (lexe list / rollback / update) is UB.
// The witness triple "1", "01", "0a" broke transitivity under the old raw
// byte-compare: "1"=="01" numerically, yet byte-compare gave "1">"0a" while
// "01"<"0a". The class-partition rule fixes it.
TEST_CASE("version order is a strict weak ordering (no std::sort UB)") {
    lexe::test::TempLexeHome home;

    // The witness triple is now consistent: "1"=="01", and both sort below the
    // non-numeric "0a" (numeric class precedes non-numeric class).
    CHECK(lexe::compare_versions("1", "01") == 0);
    CHECK(lexe::compare_versions("1", "0a") == -1);
    CHECK(lexe::compare_versions("01", "0a") == -1); // was +? inconsistent before
    // Equivalence must be transitive: 1≡01 ⇒ (1<x) ⇔ (01<x) for every x.
    for (const char* x : {"0a", "0", "2", "a", "1.0", "", "00", "z"}) {
        CAPTURE(x);
        CHECK(lexe::version_less("1", x) == lexe::version_less("01", x));
        CHECK(lexe::version_less(x, "1") == lexe::version_less(x, "01"));
    }

    // Exhaustively check the three SWO axioms over a corpus that mixes the
    // hard cases (leading zeros, mixed classes, prefixes, long digits).
    static constexpr const char* corpus[] = {
        "1", "01", "001", "0a", "0", "00", "2", "10", "10a", "9", "1.0",
        "1.0.0", "1.00", "a", "A", "z", "", "1.", "1.2", "1.10", "2.0",
    };
    const auto& lt = lexe::version_less;
    for (const char* a : corpus) {
        CHECK_FALSE(lt(a, a)); // irreflexivity
        for (const char* b : corpus) {
            // asymmetry: not both a<b and b<a (double parens: doctest cannot
            // decompose && inside CHECK).
            const bool asymmetric = !(lt(a, b) && lt(b, a));
            CHECK(asymmetric);
            for (const char* c : corpus) {
                // transitivity of <  and transitivity of equivalence
                if (lt(a, b) && lt(b, c)) { CAPTURE(a); CAPTURE(b); CAPTURE(c); CHECK(lt(a, c)); }
                const bool eq_ab = !lt(a, b) && !lt(b, a);
                const bool eq_bc = !lt(b, c) && !lt(c, b);
                if (eq_ab && eq_bc) {
                    const bool eq_ac = !lt(a, c) && !lt(c, a);
                    CAPTURE(a); CAPTURE(b); CAPTURE(c);
                    CHECK(eq_ac);
                }
            }
        }
    }

    // And the payoff: std::sort must not trip over it (a non-SWO comparator is
    // UB). Sort from two different starting orders; each result must be a valid
    // non-decreasing ordering. (They need NOT be byte-identical: std::sort is
    // not stable, so equivalent elements like "1"/"01"/"001" may sit in
    // different relative positions — that is not an ordering violation.)
    std::vector<std::string> v1(std::begin(corpus), std::end(corpus));
    std::vector<std::string> v2(v1.rbegin(), v1.rend());
    std::sort(v1.begin(), v1.end(), lt);
    std::sort(v2.begin(), v2.end(), lt);
    for (const std::vector<std::string>* v : {&v1, &v2}) {
        for (std::size_t i = 1; i < v->size(); ++i) {
            CAPTURE((*v)[i - 1]);
            CAPTURE((*v)[i]);
            CHECK_FALSE(lt((*v)[i], (*v)[i - 1])); // non-decreasing
        }
    }
}

} // TEST_SUITE("versioncmp")
