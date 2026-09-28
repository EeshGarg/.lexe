/* What the standard handles ARE, as opposed to what is written to them.
 *
 * Every other specimen here uses stdout through the C runtime. This one asks the
 * OS about the handles themselves: GetStdHandle, GetFileType, GetConsoleMode, and
 * WriteFile straight to the handle with no FILE * in between.
 *
 * The declared values describe how THIS CORPUS runs its specimens -- the generator
 * always gives a specimen pipes for all three streams -- so FILE_TYPE_PIPE is a
 * property of the fixture harness, and it is declared rather than observed on
 * purpose: if a layer ever hands the guest something else, that is exactly the
 * kind of difference this corpus exists to catch.
 *
 * GetConsoleMode on a pipe must FAIL. A great deal of real Windows software calls
 * it to decide whether it is being run interactively, and a layer that answers
 * "yes, and here is a console mode" for a pipe changes that decision.
 */
#include "oracle_win.h"

static const char *type_name(DWORD t) {
    switch (t) {
    case FILE_TYPE_UNKNOWN: return "unknown";
    case FILE_TYPE_DISK:    return "disk";
    case FILE_TYPE_CHAR:    return "char";
    case FILE_TYPE_PIPE:    return "pipe";
    default:                return "other";
    }
}

static void describe(DWORD which, const char *label) {
    char key[128];
    HANDLE h = GetStdHandle(which);
    DWORD mode = 0;
    snprintf(key, sizeof key, "%s_HANDLE_VALID", label);
    orc_kv(key, "%s", (h != NULL && h != INVALID_HANDLE_VALUE) ? "yes" : "no");
    snprintf(key, sizeof key, "%s_FILE_TYPE", label);
    orc_kv(key, "%s", type_name(GetFileType(h)));
    SetLastError(0);
    snprintf(key, sizeof key, "%s_GETCONSOLEMODE", label);
    orc_kv(key, "%s", GetConsoleMode(h, &mode) ? "ok" : "fail");
    snprintf(key, sizeof key, "%s_GETCONSOLEMODE_ERROR", label);
    orc_werr_now(key);
}

int main(void) {
    HANDLE out;
    DWORD written = 0;
    orc_begin("pe-io-standard-handles");

    describe(STD_INPUT_HANDLE, "STDIN");
    describe(STD_OUTPUT_HANDLE, "STDOUT");
    describe(STD_ERROR_HANDLE, "STDERR");

    orc_check("STD_HANDLES_ARE_DISTINCT",
              GetStdHandle(STD_OUTPUT_HANDLE) != GetStdHandle(STD_ERROR_HANDLE));

    /* WriteFile straight to the handle, bypassing the C runtime entirely. This is
     * a different path through the layer than every other specimen's printf. */
    out = GetStdHandle(STD_OUTPUT_HANDLE);
    orc_check("WRITEFILE_TO_STD_HANDLE",
              WriteFile(out, "RAW_WRITEFILE=yes\n", 18, &written, NULL) != 0);
    orc_kv("RAW_WRITEFILE_BYTES", "%lu", (unsigned long)written);
    orc_check("RAW_WRITE_WROTE_EVERYTHING", written == 18);

    /* A console-subsystem process with no console attached: whether one exists at
     * all is a property of the environment, so it is an observation. */
    orc_obs("GETCONSOLEWINDOW_NON_NULL", "%s", GetConsoleWindow() ? "yes" : "no");
    {
        DWORD pids[4];
        DWORD n = GetConsoleProcessList(pids, 4);
        orc_obs("CONSOLE_PROCESS_LIST_COUNT", "%lu", (unsigned long)n);
    }
    orc_obs("CONSOLE_OUTPUT_CP", "%u", (unsigned)GetConsoleOutputCP());
    orc_obs("ACP", "%u", (unsigned)GetACP());
    orc_obs("OEMCP", "%u", (unsigned)GetOEMCP());

    /* CONOUT$ is the console's own device, whatever stdout happens to be. Whether
     * it can be opened depends on whether there is a console, so that is an
     * observation too -- but the process must survive either answer. */
    {
        HANDLE con = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
                                 OPEN_EXISTING, 0, NULL);
        orc_obs("CONOUT_OPENABLE", "%s", con != INVALID_HANDLE_VALUE ? "yes" : "no");
        if (con != INVALID_HANDLE_VALUE) CloseHandle(con);
    }

    /* Redirecting one's OWN stdout handle at runtime, and putting it back. */
    {
        HANDLE original = GetStdHandle(STD_OUTPUT_HANDLE);
        HANDLE file = CreateFileW(L"rerouted.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        orc_check("OPENED_REROUTE_TARGET", file != INVALID_HANDLE_VALUE);
        if (file != INVALID_HANDLE_VALUE) {
            orc_check("SET_STD_HANDLE", SetStdHandle(STD_OUTPUT_HANDLE, file) != 0);
            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "REROUTED=yes\n", 13, &written, NULL);
            orc_check("RESTORED_STD_HANDLE", SetStdHandle(STD_OUTPUT_HANDLE, original) != 0);
            CloseHandle(file);
            orc_check("STD_HANDLE_IS_BACK", GetStdHandle(STD_OUTPUT_HANDLE) == original);
            {
                char buf[64];
                DWORD got = 0;
                HANDLE f = CreateFileW(L"rerouted.txt", GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                buf[0] = 0;
                if (f != INVALID_HANDLE_VALUE) {
                    ReadFile(f, buf, sizeof buf - 1, &got, NULL);
                    buf[got] = 0;
                    CloseHandle(f);
                }
                orc_kv("REROUTED_FILE_BYTES", "%lu", (unsigned long)got);
                orc_check("REROUTED_WRITE_LANDED_IN_THE_FILE",
                          strstr(buf, "REROUTED=yes") != NULL);
            }
        }
    }
    return orc_end();
}
