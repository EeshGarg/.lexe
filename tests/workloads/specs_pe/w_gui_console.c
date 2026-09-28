/* A CONSOLE-subsystem program that creates a window.
 *
 * This is not the same case as w_gui_window.c, and the difference is the point.
 * w_gui_window.c is linked -mwindows: the PE says GUI, so it has no console at
 * all and its only channel is the oracle file. This one is an ordinary console
 * PE -- it has a main(), it has stdout, it is what you get from `gcc` with no
 * subsystem flag -- and it ALSO puts a window on the screen.
 *
 * Enormous amounts of real Windows software is shaped exactly like this: SDL and
 * GLFW programs, debug builds of games, anything built without -mwindows. A
 * runtime that decides whether a program needs a display by reading the PE
 * subsystem is wrong about every one of them, and it is wrong about this specimen
 * in the opposite direction from w_gui_headless.c.
 */
#include "oracle_win.h"

static int painted = 0, closed = 0, sized = 0;

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        BeginPaint(h, &ps);
        EndPaint(h, &ps);
        painted++;
        return 0;
    }
    if (m == WM_SIZE) { sized++; return 0; }
    if (m == WM_CLOSE) { closed++; PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}

int main(int argc, char **argv) {
    WNDCLASSEXW wc;
    HWND hwnd, child;
    MSG msg;
    HINSTANCE inst = GetModuleHandleW(NULL);
    int pumped = 0;
    (void)argc; (void)argv;
    orc_begin("pe-gui-console-subsystem-window");
    orc_kv("SUBSYSTEM_DECLARED", "console");
    orc_kv("HAS_STDOUT", "%s", GetStdHandle(STD_OUTPUT_HANDLE) ? "yes" : "no");

    ZeroMemory(&wc, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = L"LexeConsoleSubsystemWindow";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    orc_check("REGISTER_CLASS", RegisterClassExW(&wc) != 0);
    hwnd = CreateWindowExW(0, L"LexeConsoleSubsystemWindow", L"Lexe Console Window",
                           WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                           400, 300, NULL, NULL, inst, NULL);
    orc_check("CREATE_WINDOW", hwnd != NULL);
    if (!hwnd) {
        orc_werr_now("CREATE_WINDOW_ERROR");
        orc_kv("WINDOW_REACHED_SCREEN", "no");
        orc_end();
        return 1;
    }
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    orc_check("WINDOW_VISIBLE", IsWindowVisible(hwnd) != 0);

    /* A CHILD window inside it: a different creation path, and the one every
     * toolkit uses for its controls. */
    child = CreateWindowExW(0, L"STATIC", L"child", WS_CHILD | WS_VISIBLE,
                            10, 10, 100, 30, hwnd, NULL, inst, NULL);
    orc_check("CREATE_CHILD_WINDOW", child != NULL);
    if (child) {
        orc_check("CHILD_PARENT_IS_THE_WINDOW", GetParent(child) == hwnd);
        orc_check("CHILD_IS_VISIBLE", IsWindowVisible(child) != 0);
        orc_kv("CHILD_CLASS_IS_A_SYSTEM_CLASS", "yes");
    }
    /* Window text set and read back: a round trip through the window manager. */
    orc_check("SET_WINDOW_TEXT", SetWindowTextW(hwnd, L"Lexe Retitled") != 0);
    {
        wchar_t title[64];
        int n = GetWindowTextW(hwnd, title, 64);
        orc_kv("WINDOW_TEXT_LENGTH", "%d", n);
        orc_check("WINDOW_TEXT_ROUNDTRIPPED", n > 0 && wcscmp(title, L"Lexe Retitled") == 0);
    }
    orc_check("MOVE_WINDOW", MoveWindow(hwnd, 20, 20, 360, 240, TRUE) != 0);
    {
        RECT r;
        if (GetClientRect(hwnd, &r)) {
            orc_kv("CLIENT_WIDTH", "%ld", (long)(r.right - r.left));
            orc_kv("CLIENT_HEIGHT", "%ld", (long)(r.bottom - r.top));
            orc_check("CLIENT_AREA_IS_SMALLER_THAN_THE_WINDOW",
                      (r.right - r.left) <= 360 && (r.bottom - r.top) <= 240);
        }
    }

    PostMessageW(hwnd, WM_CLOSE, 0, 0);
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        if (++pumped > 2000) break;
    }
    orc_kv("WM_PAINT_SEEN", "%s", painted > 0 ? "yes" : "no");
    orc_kv("WM_SIZE_SEEN", "%s", sized > 0 ? "yes" : "no");
    orc_kv("WM_CLOSE_SEEN", "%s", closed > 0 ? "yes" : "no");
    orc_obs("MESSAGES_DISPATCHED", "%d", pumped);
    orc_kv("WINDOW_REACHED_SCREEN", "yes");
    orc_kv("CONSOLE_PE_CAN_OWN_A_WINDOW", "yes");
    orc_check("MESSAGE_LOOP_COMPLETED", closed > 0 && pumped > 0);
    return orc_end();
}
