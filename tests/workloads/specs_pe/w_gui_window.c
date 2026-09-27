/* A real Win32 GUI application: a registered window class, a created and shown
 * top-level window, and a message loop that dispatches until it quits.
 *
 * It closes itself by posting WM_CLOSE, so it is bounded and needs nobody to
 * click anything -- but it is a genuine window on a genuine display, which is why
 * it must only ever run on a private X server (scripts/lib/private-display.sh),
 * never on the developer's desktop.
 *
 * Its oracle goes to the FILE: a GUI-subsystem PE has no console, so stdout is
 * not a channel that exists here. */
#include "oracle_win.h"

static int painted = 0, closed = 0;

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        (void)dc;
        EndPaint(h, &ps);
        painted++;
        return 0;
    }
    if (m == WM_CLOSE) { closed++; PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
    WNDCLASSEXW wc;
    HWND hwnd;
    MSG msg;
    int pumped = 0;
    (void)prev; (void)cmd; (void)show;
    orc_begin("pe-gui-window");
    ZeroMemory(&wc, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = L"LexeWorkloadWindow";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    orc_check("REGISTER_CLASS", RegisterClassExW(&wc) != 0);
    hwnd = CreateWindowExW(0, L"LexeWorkloadWindow", L"Lexe Workload Window",
                           WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                           480, 320, NULL, NULL, inst, NULL);
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
    {
        RECT r;
        if (GetClientRect(hwnd, &r))
            orc_obs("CLIENT_SIZE", "%ldx%ld", (long)(r.right - r.left), (long)(r.bottom - r.top));
    }
    PostMessageW(hwnd, WM_CLOSE, 0, 0);
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        if (++pumped > 2000) break;
    }
    orc_kv("MESSAGES_DISPATCHED_NONZERO", "%s", pumped > 0 ? "yes" : "no");
    orc_kv("WM_PAINT_SEEN", "%s", painted > 0 ? "yes" : "no");
    orc_kv("WM_CLOSE_SEEN", "%s", closed > 0 ? "yes" : "no");
    orc_obs("MESSAGES_DISPATCHED", "%d", pumped);
    orc_kv("WINDOW_REACHED_SCREEN", "yes");
    orc_check("MESSAGE_LOOP_COMPLETED", closed > 0 && pumped > 0);
    return orc_end();
}
