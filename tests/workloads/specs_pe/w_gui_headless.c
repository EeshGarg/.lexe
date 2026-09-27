/* A GUI-subsystem PE that never creates a window: a console-less process whose
 * only channel is the file it writes. Real Windows software does this (updaters,
 * background helpers), and it is the case where a runtime that assumes "GUI
 * subsystem means it needs a display" is wrong. */
#include "oracle_win.h"

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
    (void)inst; (void)prev; (void)cmd; (void)show;
    orc_begin("pe-gui-headless-worker");
    orc_kv("SUBSYSTEM_DECLARED", "windows");
    orc_kv("CREATES_WINDOW", "no");
    orc_kv("NEEDS_DISPLAY", "no");
    {
        unsigned long long x = 0x9E3779B97F4A7C15ULL;
        int i;
        for (i = 0; i < 1000000; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; }
        orc_kv("WORK_CHECKSUM", "%016llx", x);
    }
    {
        FILE *f = fopen("headless.out", "w");
        orc_check("WROTE_OUTPUT_FILE", f != NULL);
        if (f) { fprintf(f, "HEADLESS_RAN=yes\n"); fclose(f); }
    }
    orc_check("COMPLETED_WITHOUT_DISPLAY", 1);
    return orc_end();
}
