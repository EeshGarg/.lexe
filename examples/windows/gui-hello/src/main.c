/* windows-gui — the payload of an `applicationType: "windows"` package that
 * actually puts a WINDOW on screen.
 *
 * ../windows-hello is a console program, and it proves a foreign-OS PROCESS
 * runs: its stdout crosses the compatibility boundary, its arguments arrive, its
 * private data root is writable from inside Windows. What it cannot show is that
 * a foreign-OS window MAPS, which is a different question with a different set of
 * things that can go wrong — the compatibility layer has to reach a display, the
 * sandbox has to have a display socket bound, and the window manager has to see a
 * top-level window appear.
 *
 * So this is a real Win32 GUI program: RegisterClass, CreateWindow, a message
 * loop, and WM_PAINT. Built with -mwindows, so the PE header says GUI subsystem
 * and no console is allocated — which `lexe inspect` reports, and which is the
 * header-level difference from the console example.
 *
 * Two flags, and the reason for each:
 *
 *   --window-for <n>   open the window, then close it and exit 0 after n
 *                      seconds. Without this an automated test could show either
 *                      that a window appeared OR that the exit code was real,
 *                      never both: a windowed run would have to be killed, and a
 *                      kill makes the result a signal rather than an exit.
 *
 *   --selftest         write into LEXE_APP_DATA and read it back, then exit,
 *                      without touching the display at all. The headless check,
 *                      for a host with no display to open.
 *
 * The window title is deliberately distinctive: an acceptance check matches on it
 * with xwininfo, and "Window" or "Test" would match half a desktop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#define APP_TITLE "Lexe Windows GUI"

static const char *env_or(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

/* Note every start in the private data root, BEFORE touching the display.
 *
 * This is what makes a launch provable even when nothing rendered: the file is
 * written by a Windows process, into a directory the Linux sandbox bound, so its
 * existence is evidence that the whole chain ran. Wine maps the Linux path
 * through the Z: drive, so LEXE_APP_DATA (a POSIX path) is usable directly. */
static void note_launch(const char *how) {
    const char *data = getenv("LEXE_APP_DATA");
    if (data == NULL || data[0] == '\0') return;
    char path[2048];
    snprintf(path, sizeof path, "%s/windows-gui-launches.log", data);
    FILE *log = fopen(path, "a");
    if (log == NULL) return;
    fprintf(log, "%s\n", how);
    fclose(log);
}

/* Everything the window shows, minus the window: the headless check. */
static int run_selftest(void) {
    note_launch("selftest");
    printf("%s selftest\n", APP_TITLE);
    printf("  Windows API version:  %lu.%lu\n",
           (unsigned long)(GetVersion() & 0xFF),
           (unsigned long)((GetVersion() >> 8) & 0xFF));
    printf("  LEXE_APP_ID:          %s\n", env_or("LEXE_APP_ID", "(unset)"));
    printf("  LEXE_APP_DATA:        %s\n", env_or("LEXE_APP_DATA", "(unset)"));

    const char *data = getenv("LEXE_APP_DATA");
    if (data == NULL || data[0] == '\0') {
        printf("selftest: FAIL (no LEXE_APP_DATA)\n");
        return 1;
    }
    char path[2048];
    snprintf(path, sizeof path, "%s/windows-gui-selftest.txt", data);
    FILE *out = fopen(path, "w");
    if (out == NULL) {
        printf("selftest: FAIL (cannot write to LEXE_APP_DATA)\n");
        return 1;
    }
    fputs("written from a Windows process\n", out);
    fclose(out);

    FILE *back = fopen(path, "r");
    if (back == NULL) {
        printf("selftest: FAIL (cannot read back what it wrote)\n");
        return 1;
    }
    char line[256] = {0};
    const char *read_ok = fgets(line, (int)sizeof line, back);
    fclose(back);
    if (read_ok == NULL || strncmp(line, "written", 7) != 0) {
        printf("selftest: FAIL (read back the wrong bytes)\n");
        return 1;
    }
    printf("selftest: PASS\n");
    return 0;
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam,
                                    LPARAM lparam) {
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT paint;
        HDC dc = BeginPaint(window, &paint);
        /* Text rather than graphics on purpose: a screenshot of this window is
         * evidence about the environment, so it says what the environment is. */
        char lines[4][512];
        snprintf(lines[0], sizeof lines[0], "%s", APP_TITLE);
        snprintf(lines[1], sizeof lines[1], "A Windows PE, on Linux, sandboxed.");
        snprintf(lines[2], sizeof lines[2], "LEXE_APP_ID:   %s",
                 env_or("LEXE_APP_ID", "(unset)"));
        snprintf(lines[3], sizeof lines[3], "LEXE_APP_DATA: %s",
                 env_or("LEXE_APP_DATA", "(unset)"));
        for (int i = 0; i < 4; ++i) {
            TextOutA(dc, 16, 16 + i * 22, lines[i], (int)strlen(lines[i]));
        }
        EndPaint(window, &paint);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcA(window, message, wparam, lparam);
    }
}

int main(int argc, char **argv) {
    long window_for = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--selftest") == 0) return run_selftest();
        if (strcmp(argv[i], "--window-for") == 0 && i + 1 < argc) {
            window_for = strtol(argv[i + 1], NULL, 10);
            if (window_for < 1) window_for = 1;
            if (window_for > 120) window_for = 120;
            ++i;
            continue;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("usage: windows-gui [--selftest] [--window-for <seconds>]\n"
                   "  --selftest          report the .LEXE launch environment "
                   "and verify\n"
                   "                      $LEXE_APP_DATA is writable, without "
                   "opening a window\n"
                   "  --window-for <n>    open the window, then close it and "
                   "exit 0 after n\n"
                   "                      seconds, so a test can witness the "
                   "window AND a real\n"
                   "                      exit code\n");
            return 0;
        }
    }

    note_launch("gui");

    const HINSTANCE instance = GetModuleHandleA(NULL);
    WNDCLASSA klass;
    memset(&klass, 0, sizeof klass);
    klass.lpfnWndProc = window_proc;
    klass.hInstance = instance;
    klass.lpszClassName = "LexeWindowsGui";
    klass.hCursor = LoadCursorA(NULL, IDC_ARROW);
    klass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    if (RegisterClassA(&klass) == 0) {
        fprintf(stderr, "windows-gui: RegisterClass failed (%lu)\n",
                (unsigned long)GetLastError());
        return 2;
    }

    const HWND window = CreateWindowExA(
        0, klass.lpszClassName, APP_TITLE, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
        CW_USEDEFAULT, 560, 220, NULL, NULL, instance, NULL);
    if (window == NULL) {
        /* No display is a legitimate outcome, not a crash: say so and exit 2,
         * the same way the native GUI example does, so a headless host gets a
         * clear message instead of a silent failure. */
        fprintf(stderr,
                "windows-gui: could not create a window (%lu) — no display?\n"
                "windows-gui: run with --selftest for the headless check.\n",
                (unsigned long)GetLastError());
        return 2;
    }

    ShowWindow(window, SW_SHOWNORMAL);
    UpdateWindow(window);
    printf("windows-gui: window open for %ld second(s)\n",
           window_for > 0 ? window_for : 0L);
    fflush(stdout);

    if (window_for > 0) {
        /* A timer rather than a sleep: the message loop has to keep running or
         * the window never paints and a window manager may never see it map. */
        SetTimer(window, 1, (UINT)(window_for * 1000), NULL);
    }

    MSG message;
    while (GetMessageA(&message, NULL, 0, 0) > 0) {
        if (message.message == WM_TIMER) {
            DestroyWindow(window);
            continue;
        }
        TranslateMessage(&message);
        DispatchMessageA(&message);
    }
    return 0;
}
