/* An unusual exit code, chosen deliberately and passed to ExitProcess.
 *
 * A Windows exit status is a full 32-bit DWORD; a Unix wait status carries eight
 * bits. So a program that exits 256 is indistinguishable, to the Unix caller of a
 * translation layer, from one that exited 0 -- and a program that exits
 * 0xC0000005 on purpose is indistinguishable from one that died of an access
 * violation. Both of those are real, both are legitimate programs, and both are
 * things a supervisor gets wrong.
 *
 * The specimen records the full 32-bit value it intended in its oracle FILE
 * before it exits, so the intent survives the truncation and a consumer can tell
 * the two cases apart from the evidence rather than from the status alone.
 */
#include "oracle_win.h"

int main(int argc, char **argv) {
    unsigned long code = argc > 1 ? strtoul(argv[1], NULL, 10) : 0;
    orc_begin("pe-outcome-exitcode");
    orc_kv("EXIT_CODE_INTENDED", "%lu", code);
    orc_kv("EXIT_CODE_INTENDED_HEX", "0x%08lx", code);
    orc_kv("EXIT_CODE_LOW_BYTE", "%lu", code & 0xFFu);
    orc_kv("EXIT_CODE_EXCEEDS_8_BITS", "%s", code > 0xFFu ? "yes" : "no");
    orc_kv("EXIT_CODE_LOOKS_LIKE_NT_STATUS", "%s",
           (code & 0xC0000000u) == 0xC0000000u ? "yes" : "no");
    orc_kv("DIED_ABNORMALLY", "no");
    orc_kv("WORK_DONE", "yes");
    orc_end();
    ExitProcess((UINT)code);
    return 0;
}
