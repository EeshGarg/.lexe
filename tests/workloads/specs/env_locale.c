/* A locale is a claim about the host, not a preference.
 *
 *   argv[1]  a locale name to request, or "-" to request none
 *
 * setlocale() returning NULL does not mean the program is broken: it means the
 * host does not have that locale installed, which is a fact about the machine.
 * This host has exactly three (C, C.utf8, POSIX) and no en_US.UTF-8 at all, so a
 * program that assumes a named locale exists fails here for entirely legitimate
 * reasons -- and the corpus needs a specimen that DEMONSTRATES that rather than
 * a corpus that quietly avoids it.
 *
 * What the specimen asserts is only what is invariant: that the C locale always
 * exists, that MB_CUR_MAX is 1 in it, and that a UTF-8 string round-trips
 * through mbstowcs/wcstombs when a UTF-8 locale IS in effect. Whether the
 * REQUESTED locale exists is reported, per specimen, as a declared expectation --
 * present for C.UTF-8 and absent for en_US.UTF-8 -- so "this host does not have
 * that locale" is measured and declared instead of discovered at the point where
 * something else is being tested.
 */
#include "oracle.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define UTF8_SAMPLE "café-日本-Ωmega"

int main(int argc, char **argv) {
    const char *want = argc > 1 ? argv[1] : "-";
    const char *got;
    wchar_t wide[64];
    char back[128];
    size_t wn, bn;

    orc_begin("linux-env-locale");
    orc_kv("REQUESTED_LOCALE", "%s", want);

    /* The C locale is guaranteed by the standard: if this fails the host is
     * broken in a way no specimen can work around. */
    got = setlocale(LC_ALL, "C");
    orc_check("C_LOCALE_AVAILABLE", got != NULL);
    orc_kv("C_LOCALE_MB_CUR_MAX", "%d", (int)MB_CUR_MAX);
    orc_check("C_LOCALE_IS_SINGLE_BYTE", MB_CUR_MAX == 1);

    if (strcmp(want, "-") == 0) {
        /* The empty string means "whatever the environment says", which is the
         * single most environment-dependent call in the C library. */
        got = setlocale(LC_ALL, "");
        orc_kv("ENV_LOCALE_ACCEPTED", "%s", got ? "yes" : "no");
        orc_obs("ENV_LOCALE_NAME", "%s", got ? got : "(null)");
    } else {
        got = setlocale(LC_ALL, want);
        orc_kv("REQUESTED_LOCALE_AVAILABLE", "%s", got ? "yes" : "no");
        orc_obs("REQUESTED_LOCALE_NAME", "%s", got ? got : "(null)");
        if (!got) {
            /* Not a failure of the program. It asked, the host said no, and it
             * carries on in the locale it already had. */
            orc_kv("FELL_BACK_TO", "C");
            orc_kv("MB_CUR_MAX_AFTER_REFUSAL", "%d", (int)MB_CUR_MAX);
            orc_check("SURVIVED_MISSING_LOCALE", 1);
            return orc_end();
        }
    }

    orc_kv("MB_CUR_MAX", "%d", (int)MB_CUR_MAX);
    orc_kv("MULTIBYTE_IN_EFFECT", "%s", MB_CUR_MAX > 1 ? "yes" : "no");

    orc_kv("SAMPLE_BYTES", "%lu", (unsigned long)strlen(UTF8_SAMPLE));
    wn = mbstowcs(wide, UTF8_SAMPLE, sizeof wide / sizeof wide[0]);
    if (wn == (size_t)-1) {
        orc_kv("MBSTOWCS", "invalid");
        orc_check("UTF8_DECODES", 0);
        return orc_end();
    }
    orc_kv("MBSTOWCS", "ok");
    orc_kv("SAMPLE_WIDE_CHARS", "%lu", (unsigned long)wn);
    bn = wcstombs(back, wide, sizeof back);
    orc_check("WCSTOMBS_OK", bn != (size_t)-1);
    orc_check("UTF8_ROUNDTRIPS", bn != (size_t)-1 && strcmp(back, UTF8_SAMPLE) == 0);
    return orc_end();
}
