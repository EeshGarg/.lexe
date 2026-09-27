/* Translation unit 4 of 4. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    unsigned long a, b;
    report_kv("FIXTURE_ID", "%s", id ? id : "portable-c-multi-tu");
    report_kv("PAYLOAD_KIND", "%s", "portable-source");
    report_kv("TRANSLATION_UNITS", "%d", 4);
    a = util_mix(2166136261UL, 1024);
    b = calc_series(64);
    report_kv("UTIL_MIX", "%lu", a);
    report_kv("CALC_SERIES", "%lu", b);
    report_kv("BUILD_ISA", "%s", util_isa());
    report_kv("ARGC", "%d", argc);
    report_kv("OBS_BUILD_STAMP", "%s %s", __DATE__, __TIME__);
    report_check("ALL_UNITS_LINKED", a != 0 && b != 0);
    report_check("UTIL_MIX_STABLE", util_mix(2166136261UL, 1024) == a);
    report_check("CALC_SERIES_STABLE", calc_series(64) == b);
    report_check("ISA_KNOWN", strcmp(util_isa(), "unknown") != 0);
    report_kv("RESULT", "%s", report_failures() == 0 ? "PASS" : "FAIL");
    (void)argv;
    return 0;
}
