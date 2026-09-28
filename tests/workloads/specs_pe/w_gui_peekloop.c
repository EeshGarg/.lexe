/* A GAME loop, not an application loop.
 *
 * w_gui_window.c uses GetMessageW, which BLOCKS until there is a message: that is
 * how a document application waits for the user. A game does the opposite -- it
 * drains the queue with PeekMessage and then renders a frame whether or not
 * anything happened, as fast as it can, forever. That makes the message pump a
 * poll rather than a wait, and it is the shape almost every real-time Windows
 * program has.
 *
 * It matters here because the two are completely different paths through a
 * window-system emulation: GetMessage can sleep in the layer, PeekMessage has to
 * return immediately and truthfully say "nothing", thousands of times a second. A
 * PeekMessage that blocks, or that lies, turns a 120-frame run into a hang.
 *
 * The frame count is exact -- the loop closes itself on frame 120 -- and a
 * WM_TIMER is set up alongside so the queue really does get traffic between frames.
 */
#include "oracle_win.h"

#define TARGET_FRAMES 120

static int timer_ticks = 0, closed = 0, painted = 0;

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_TIMER) { timer_ticks++; return 0; }
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

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
    WNDCLASSEXW wc;
    HWND hwnd;
    MSG msg;
    int frames = 0, peek_returned_nothing = 0, messages = 0, running = 1;
    LARGE_INTEGER freq, t0, t1;
    (void)prev; (void)cmd; (void)show;
    orc_begin("pe-gui-peek-message-loop");

    ZeroMemory(&wc, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = L"LexeGameLoopWindow";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    orc_check("REGISTER_CLASS", RegisterClassExW(&wc) != 0);
    hwnd = CreateWindowExW(0, L"LexeGameLoopWindow", L"Lexe Game Loop",
                           WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                           320, 240, NULL, NULL, inst, NULL);
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
    orc_check("SET_TIMER", SetTimer(hwnd, 1, 10, NULL) != 0);

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    while (running) {
        /* The non-blocking drain. */
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            messages++;
            if (msg.message == WM_QUIT) { running = 0; break; }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (messages > 100000) { running = 0; break; }
        }
        if (!running) break;
        peek_returned_nothing++;      /* the queue was empty: a real frame boundary */
        frames++;
        /* The loop ends on a frame count the PROGRAM chose, not on whenever
         * WM_QUIT happens to be dequeued. Leaving that to the queue would make
         * FRAMES_RENDERED depend on message-delivery timing, and a deterministic
         * oracle key whose value depends on timing is a fixture bug waiting to be
         * blamed on something else. */
        if (frames == TARGET_FRAMES) { PostMessageW(hwnd, WM_CLOSE, 0, 0); running = 0; }
        Sleep(1);
    }
    /* A bounded drain so WM_CLOSE really is delivered and WM_CLOSE_SEEN means
     * something, without letting the frame counter move. */
    {
        int drained = 0;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE) && drained++ < 64) {
            messages++;
            if (msg.message == WM_QUIT) break;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    QueryPerformanceCounter(&t1);
    KillTimer(hwnd, 1);

    orc_kv("FRAMES_RENDERED", "%d", frames);
    orc_kv("TARGET_FRAMES", "%d", TARGET_FRAMES);
    orc_obs("MESSAGES_PUMPED", "%d", messages);
    orc_obs("TIMER_TICKS", "%d", timer_ticks);
    orc_obs("LOOP_MS", "%.0f",
            (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart);
    orc_kv("WM_CLOSE_SEEN", "%s", closed > 0 ? "yes" : "no");
    orc_kv("WM_TIMER_SEEN", "%s", timer_ticks > 0 ? "yes" : "no");
    orc_kv("PEEK_MESSAGE_REPORTED_AN_EMPTY_QUEUE", "%s",
           peek_returned_nothing > 0 ? "yes" : "no");
    orc_kv("WINDOW_REACHED_SCREEN", "yes");
    /* The loop ran to its own target and then stopped because IT decided to, which
     * is the difference between a game loop and a hang. */
    orc_check("LOOP_REACHED_ITS_TARGET_AND_STOPPED",
              frames == TARGET_FRAMES && closed > 0);
    orc_check("PEEK_MESSAGE_DID_NOT_BLOCK", peek_returned_nothing >= TARGET_FRAMES);
    orc_check("TIMER_MESSAGES_ARRIVED_BETWEEN_FRAMES", timer_ticks > 0);
    orc_check("PAINTED_AT_LEAST_ONCE", painted > 0);
    return orc_end();
}
