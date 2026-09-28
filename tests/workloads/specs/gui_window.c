/* A real window on a real X server. No toolkit, just Xlib.
 *
 *   argv[1]  map | twowin | hold | orphan | crash | nodisplay
 *   argv[2]  milliseconds to hold the window up (modes hold/orphan)
 *
 * The ELF corpus had no GUI specimen at all, which left a whole class of
 * legitimate program unrepresented: one that needs a display, maps a top-level
 * window, and whose visible state is the thing worth observing. Raw Xlib rather
 * than a toolkit because a toolkit would add a dozen libraries and a settings
 * daemon between the specimen and the property under test.
 *
 * NO AUTOMATED TEST MAY PUT A WINDOW ON THE DEVELOPER'S SCREEN. The generator
 * runs every mode but `nodisplay` on the project's own namespaced private X
 * server (scripts/lib/private-display.sh), inside a private mount AND network
 * namespace where the user's real display is not merely unbound but invisible.
 *
 * What is asserted is the window's own state read back from the server -- its
 * geometry, and map_state == IsViewable, which is the server agreeing that the
 * window is on screen -- never a screenshot and never a pixel.
 *
 * `nodisplay` is the same binary with DISPLAY unset. XOpenDisplay returns NULL,
 * the specimen says so and exits 3. That is the pair that matters: one binary,
 * one difference in the environment, two fully declared outcomes, so "the GUI
 * program did not start" is distinguishable from "the GUI program was never run".
 */
#include "oracle.h"

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define W 320
#define H 200

static const char *map_state_name(int s) {
    switch (s) {
    case IsUnmapped:   return "unmapped";
    case IsUnviewable: return "unviewable";
    case IsViewable:   return "viewable";
    default:           return "unknown";
    }
}

/* Create one top-level window, map it, and wait until the server reports it
 * viewable. MapWindow is asynchronous: without the round trip the answer would
 * be a race rather than a measurement. */
static Window make_window(Display *d, const char *title, int x, int y) {
    int s = DefaultScreen(d);
    Window w = XCreateSimpleWindow(d, RootWindow(d, s), x, y, W, H, 1,
                                   BlackPixel(d, s), WhitePixel(d, s));
    XStoreName(d, w, title);
    XSelectInput(d, w, ExposureMask | StructureNotifyMask);
    XMapWindow(d, w);
    XFlush(d);
    return w;
}

static int wait_viewable(Display *d, Window w, XWindowAttributes *a) {
    int i;
    for (i = 0; i < 200; i++) {
        XSync(d, False);
        if (XGetWindowAttributes(d, w, a) && a->map_state == IsViewable)
            return 1;
        usleep(10000);
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "map";
    int hold_ms = argc > 2 ? atoi(argv[2]) : 0;
    Display *d;
    Window w, w2;
    XWindowAttributes a;
    const char *disp = getenv("DISPLAY");

    orc_begin("linux-gui-window");
    orc_kv("GUI_MODE", "%s", mode);
    orc_kv("DISPLAY_SET", "%s", (disp && *disp) ? "yes" : "no");
    orc_obs("DISPLAY", "%s", disp ? disp : "(unset)");

    d = XOpenDisplay(NULL);
    if (!d) {
        /* A declared outcome, not a crash: the program needs a display and says
         * so on the oracle stream instead of dying. */
        orc_kv("XOPEN_DISPLAY", "fail");
        orc_kv("NEEDS", "an X display");
        if (strcmp(mode, "nodisplay") == 0) {
            orc_check("FAILED_AS_DECLARED", 1);
            orc_kv("RESULT", "PASS");
            fflush(stdout);
            return 3;
        }
        orc_check("FAILED_AS_DECLARED", 0);
        return 3;
    }
    orc_kv("XOPEN_DISPLAY", "ok");
    orc_obs("X_VENDOR", "%s", ServerVendor(d));
    orc_obs("X_SCREEN_WH", "%dx%d", DisplayWidth(d, DefaultScreen(d)),
            DisplayHeight(d, DefaultScreen(d)));

    if (strcmp(mode, "nodisplay") == 0) {
        /* Declared to have NO display and one was found: the isolation the whole
         * GUI family depends on is not in place, and saying so is the only
         * honest outcome. */
        orc_check("DECLARED_NO_DISPLAY_BUT_FOUND_ONE", 0);
        XCloseDisplay(d);
        return orc_end();
    }

    w = make_window(d, "lexe-workload-window", 10, 10);
    orc_check("WINDOW_CREATED", w != 0);
    orc_check("WINDOW_VIEWABLE", wait_viewable(d, w, &a));
    orc_kv("WINDOW_MAP_STATE", "%s", map_state_name(a.map_state));
    orc_kv("WINDOW_WIDTH", "%d", a.width);
    orc_kv("WINDOW_HEIGHT", "%d", a.height);
    orc_check("GEOMETRY_AS_REQUESTED", a.width == W && a.height == H);

    if (strcmp(mode, "twowin") == 0) {
        XWindowAttributes a2;
        w2 = make_window(d, "lexe-workload-window-2", 340, 10);
        orc_check("SECOND_WINDOW_CREATED", w2 != 0);
        orc_check("SECOND_WINDOW_VIEWABLE", wait_viewable(d, w2, &a2));
        orc_check("TWO_DISTINCT_WINDOWS", w2 != w);
        orc_kv("TOP_LEVEL_WINDOWS", "2");
        XDestroyWindow(d, w2);
    } else if (strcmp(mode, "hold") == 0) {
        orc_kv("HOLD_MS", "%d", hold_ms);
        fflush(stdout);
        usleep((useconds_t)hold_ms * 1000);
        orc_check("STILL_VIEWABLE_AFTER_HOLD",
                  XGetWindowAttributes(d, w, &a) && a.map_state == IsViewable);
    } else if (strcmp(mode, "crash") == 0) {
        volatile int *p = (volatile int *)0;
        orc_kv("FAULT_KIND", "null-write-with-a-window-mapped");
        orc_expect_death("sigsegv-while-gui");
        fflush(stdout);
        *p = 1;
        orc_kv("UNREACHED", "yes");
        return 90;
    } else if (strcmp(mode, "orphan") == 0) {
        /* The GUI half survives the process that was launched. The parent exits
         * immediately; the child keeps the window up, then records what it saw
         * in a file, because by then there is nothing left to read its stdout.
         *
         * THE PARENT CLOSES ITS OWN CONNECTION BEFORE FORKING, and this is not
         * tidiness. Xlib is not fork-safe: a child that inherits a live Display
         * shares the parent's socket fd and the parent's internal buffers, and
         * the parent then tears that connection down while the child is opening
         * one of its own. The first version of this specimen forked first, and
         * it was INTERMITTENT -- it produced its file on some runs and nothing
         * at all on others, with no pattern in the environment or the load.
         * A fixture that sometimes reports nothing is not evidence, and the
         * hand-off is also the more honest shape: a launcher that gives the
         * display to a child has no business keeping a connection open. */
        pid_t pid;
        XDestroyWindow(d, w);
        XCloseDisplay(d);
        d = NULL;
        orc_kv("PARENT_CLOSED_ITS_DISPLAY_BEFORE_FORK", "yes");
        fflush(stdout);
        pid = fork();
        if (pid == 0) {
            FILE *f;
            Display *cd;
            Window cw;
            XWindowAttributes ca;
            int ok;
            /* A connection of its own, opened in a process that holds no
             * inherited Xlib state at all. */
            cd = XOpenDisplay(NULL);
            if (!cd) _exit(4);
            cw = make_window(cd, "lexe-workload-orphan-window", 10, 240);
            ok = wait_viewable(cd, cw, &ca);
            usleep((useconds_t)(hold_ms > 0 ? hold_ms : 500) * 1000);
            ok = ok && XGetWindowAttributes(cd, cw, &ca) &&
                 ca.map_state == IsViewable;
            f = fopen("gui_orphan.log", "w");
            if (f) {
                fprintf(f, "ORPHAN_WINDOW_VIEWABLE=%s\n", ok ? "yes" : "no");
                fprintf(f, "ORPHAN_WIDTH=%d\n", ca.width);
                fprintf(f, "ORPHAN_SURVIVED_PARENT=yes\n");
                fprintf(f, "ORPHAN_RESULT=PASS\n");
                fclose(f);
            }
            XDestroyWindow(cd, cw);
            XCloseDisplay(cd);
            _exit(0);
        }
        orc_check("FORK_OK", pid > 0);
        orc_kv("PARENT_EXITS_FIRST", "yes");
        orc_kv("CHILD_OWNS_THE_WINDOW", "yes");
        return orc_end();               /* the child is still on screen */
    }

    XDestroyWindow(d, w);
    XSync(d, False);
    orc_check("WINDOW_DESTROYED", 1);
    XCloseDisplay(d);
    return orc_end();
}
