/* The node in the tree that OWNS THE VISIBLE WINDOW.
 *
 * It is the only GUI-subsystem binary in the process-tree family (built with
 * -mwindows), which is itself part of what is being tested: in real Windows
 * software the process with the window and the process doing the work are very
 * often not the same process, and the window is frequently NOT owned by the top of
 * the tree. A window belongs to the thread that created it and dies with that
 * thread, so "the window outlives the process that created it" is not something any
 * program can do -- what CAN happen, and what this node arranges, is that the window
 * and its owning process outlive every process that STARTED them.
 *
 * argv[1] is the tree mode, argv[2] how long to hold the window in milliseconds.
 *
 *   gui-leaf  main starts this node DETACHED and exits at once. The window is held
 *             for the full time and closed only afterwards, so for most of its life
 *             there is a window on the screen and not one live ancestor. It checks
 *             for main's exit flag to prove that rather than assume it.
 *   gui-top   the LAUNCHER starts this node as a sibling of the payload chain and
 *             waits for it. The window is held until the WORKER at the bottom of the
 *             tree drops tree_done.flag -- so the splash comes down because of a side
 *             effect of work two levels below, which is the real launcher shape.
 *
 * Being a GUI-subsystem PE it has no console at all: the oracle FILE is its only
 * channel, which is exactly why this corpus writes one.
 */
#include "t_common.h"

static int painted = 0, closed = 0;

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        BeginPaint(h, &ps);
        EndPaint(h, &ps);
        painted++;
        return 0;
    }
    if (m == WM_CLOSE) { closed++; PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}

static void pump(HWND hwnd, int *pumped) {
    MSG msg;
    (void)hwnd;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) return;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        (*pumped)++;
    }
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmdline, int show) {
    WNDCLASSEXW wc;
    HWND hwnd;
    int argc = 0, pumped = 0, waited = 0, saw_flag = 0;
    LPWSTR *argv;
    char mode[64] = "gui-leaf";
    DWORD hold = 2500;
    (void)prev; (void)cmdline; (void)show;
    orc_begin_fixed("t_window");

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc > 1) WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, mode, 64, NULL, NULL);
    if (argv && argc > 2) hold = (DWORD)wcstoul(argv[2], NULL, 10);
    if (argv) LocalFree(argv);

    orc_kv("NODE", "window");
    orc_kv("MODE", "%s", mode);
    orc_kv("SUBSYSTEM_DECLARED", "windows");
    orc_kv("HOLD_MS", "%lu", (unsigned long)hold);
    tree_state_note("WINDOW");

    ZeroMemory(&wc, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = L"LexeTreeWindow";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    orc_check("REGISTER_CLASS", RegisterClassExW(&wc) != 0);
    hwnd = CreateWindowExW(0, L"LexeTreeWindow", L"Lexe Tree Window",
                           WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                           420, 280, NULL, NULL, inst, NULL);
    orc_check("CREATE_WINDOW", hwnd != NULL);
    if (!hwnd) {
        orc_werr_now("CREATE_WINDOW_ERROR");
        orc_kv("WINDOW_REACHED_SCREEN", "no");
        tree_flag(L"window_done.flag");
        orc_end();
        return 1;
    }
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    orc_check("WINDOW_VISIBLE", IsWindowVisible(hwnd) != 0);
    orc_kv("WINDOW_REACHED_SCREEN", "yes");
    tree_flag(L"window_up.flag");
    orc_kv("STARTER_GONE_WHEN_WINDOW_WENT_UP", "%s",
           tree_flag_present(L"main_exited.flag") ? "yes" : "no");

    /* Hold the window up, pumping so it is a real live window and not a frozen
     * one, until either the work below finishes or the hold time is up. */
    while (waited < (int)hold) {
        pump(hwnd, &pumped);
        if (tree_flag_present(L"tree_done.flag")) { saw_flag = 1; break; }
        Sleep(25);
        waited += 25;
    }
    orc_obs("HELD_MS", "%d", waited);
    orc_kv("SAW_TREE_DONE_FLAG", "%s", saw_flag ? "yes" : "no");
    orc_kv("STARTER_GONE_BEFORE_WINDOW_CAME_DOWN", "%s",
           tree_flag_present(L"main_exited.flag") ? "yes" : "no");
    orc_kv("LAUNCHER_GONE_BEFORE_WINDOW_CAME_DOWN", "%s",
           tree_flag_present(L"launcher_exited.flag") ? "yes" : "no");
    orc_check("WINDOW_STILL_ALIVE_AT_TEARDOWN", IsWindow(hwnd) != 0);

    PostMessageW(hwnd, WM_CLOSE, 0, 0);
    {
        int spins = 0;
        while (!closed && spins++ < 400) { pump(hwnd, &pumped); Sleep(5); }
    }
    orc_kv("WM_CLOSE_SEEN", "%s", closed > 0 ? "yes" : "no");
    orc_kv("WM_PAINT_SEEN", "%s", painted > 0 ? "yes" : "no");
    orc_obs("MESSAGES_DISPATCHED", "%d", pumped);
    orc_kv("WINDOW_HELD_AND_CLOSED", "yes");
    orc_check("WINDOW_LIFECYCLE_COMPLETED", closed > 0);
    tree_flag(L"window_done.flag");
    return orc_end();
}
