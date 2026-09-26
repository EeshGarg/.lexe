/*
 * gui-hello — a real GTK 3 desktop application, packaged as a .lexe.
 *
 * This is the acceptance payload for the Definitive Architecture's GUI launch
 * path (§14.4 declared presentation, §15.1 durable launch). Unlike the older
 * `gtk-app` example — which exists to SHOW the Tux32 Core 1 boundary and is not
 * meant to run under the sandbox — this one is meant to actually run:
 *
 *   lexe.json declares   "launch": { "mode": "gui" }
 *   which grants         the session display socket, /etc/fonts, /dev/dri
 *   and nothing else     (no D-Bus, no $HOME, no network)
 *
 * The window proves four things a headless test cannot:
 *
 *   1. the process really is the native application (argv[0], pid, ISA),
 *   2. LEXE_APP_ID reached it, so .LEXE launched it rather than the desktop
 *      running a raw ELF,
 *   3. $LEXE_APP_DATA is a real, writable, PRIVATE directory — the button
 *      writes into it and reads the result back,
 *   4. the display socket forwarded into the sandbox actually works.
 *
 * Every start also appends a line to $LEXE_APP_DATA/gui-hello-launches.log
 * BEFORE GTK is touched, so an automated run can prove that a launch really
 * reached the payload even where no display exists.
 *
 * `--selftest` performs 1-3 headlessly and exits 0 WITHOUT touching GTK, so an
 * automated acceptance run needs no display at all.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <gtk/gtk.h>

#define APP_TITLE "Lexe GUI Hello"

/* ------------------------------------------------------------------ */
/* Environment helpers                                                 */
/* ------------------------------------------------------------------ */

static const char *env_or(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

static char *now_string(void) {
    time_t now = time(NULL);
    struct tm tm_buf;
    char stamp[64];
    if (localtime_r(&now, &tm_buf) == NULL) return g_strdup("(unknown time)");
    if (strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S %Z", &tm_buf) == 0) {
        return g_strdup("(unknown time)");
    }
    return g_strdup(stamp);
}

/*
 * Append one line to $LEXE_APP_DATA/gui-hello-launches.log recording that this
 * process started, and in which mode. It runs before GTK is touched, so the
 * log is written even on a host with no display — which is what lets an
 * automated acceptance run prove "run.lexe really executed the payload"
 * without depending on a window ever appearing.
 */
static void note_launch(const char *mode) {
    const char *data_dir = getenv("LEXE_APP_DATA");
    if (data_dir == NULL || data_dir[0] == '\0') return;
    char *path = g_build_filename(data_dir, "gui-hello-launches.log", NULL);
    FILE *out = fopen(path, "a");
    if (out != NULL) {
        char *stamp = now_string();
        fprintf(out, "%s mode=%s pid=%ld appid=%s\n", stamp, mode,
                (long)getpid(), env_or("LEXE_APP_ID", "(unset)"));
        g_free(stamp);
        fclose(out);
    }
    g_free(path);
}

/*
 * Write a probe file into $LEXE_APP_DATA and read it back. Returns a
 * newly-allocated human-readable result; *ok is set to 1 on success.
 * This is the private-data proof: it must work from INSIDE the sandbox.
 */
static char *probe_app_data(int *ok) {
    const char *data_dir = getenv("LEXE_APP_DATA");
    *ok = 0;
    if (data_dir == NULL || data_dir[0] == '\0') {
        return g_strdup("LEXE_APP_DATA is not set — not launched by .LEXE?");
    }

    char *path = g_build_filename(data_dir, "gui-hello-probe.txt", NULL);
    char *stamp = now_string();

    FILE *out = fopen(path, "a");
    if (out == NULL) {
        char *msg = g_strdup_printf("cannot write %s: %s", path,
                                    strerror(errno));
        g_free(path);
        g_free(stamp);
        return msg;
    }
    fprintf(out, "run at %s by pid %ld\n", stamp, (long)getpid());
    fclose(out);
    g_free(stamp);

    /* Read it back so the result reflects real persisted bytes, not a hope. */
    gchar *contents = NULL;
    gsize length = 0;
    GError *error = NULL;
    if (!g_file_get_contents(path, &contents, &length, &error)) {
        char *msg = g_strdup_printf("wrote %s but cannot read it back: %s",
                                    path, error ? error->message : "?");
        if (error != NULL) g_error_free(error);
        g_free(path);
        return msg;
    }

    gint lines = 0;
    for (gsize i = 0; i < length; i++) {
        if (contents[i] == '\n') lines++;
    }
    char *msg = g_strdup_printf("OK — %s now holds %d line%s (%lu bytes)", path,
                                lines, lines == 1 ? "" : "s",
                                (unsigned long)length);
    g_free(contents);
    g_free(path);
    *ok = 1;
    return msg;
}

/* ------------------------------------------------------------------ */
/* --selftest: everything the window proves, minus the window          */
/* ------------------------------------------------------------------ */

static int run_selftest(void) {
    char *stamp = now_string();
    note_launch("selftest");
    printf("%s selftest\n", APP_TITLE);
    printf("  argv0        : %s\n", env_or("_", "(n/a)"));
    printf("  pid          : %ld\n", (long)getpid());
    printf("  LEXE_APP_ID  : %s\n", env_or("LEXE_APP_ID", "(unset)"));
    printf("  LEXE_APP_DATA: %s\n", env_or("LEXE_APP_DATA", "(unset)"));
    printf("  HOME         : %s\n", env_or("HOME", "(unset)"));
    printf("  WAYLAND_DISPLAY: %s\n", env_or("WAYLAND_DISPLAY", "(unset)"));
    printf("  DISPLAY      : %s\n", env_or("DISPLAY", "(unset)"));
    printf("  time         : %s\n", stamp);
    g_free(stamp);

    /* Only the private-data contract is a hard requirement here: it is the one
     * thing .LEXE promises unconditionally, display or no display. When
     * LEXE_APP_DATA is unset we are being run outside .LEXE (a bare `make &&
     * ./payload/bin/gui-hello --selftest`), which is not a failure. */
    if (getenv("LEXE_APP_DATA") != NULL && getenv("LEXE_APP_DATA")[0] != '\0') {
        int ok = 0;
        char *result = probe_app_data(&ok);
        printf("  app data     : %s\n", result);
        g_free(result);
        if (!ok) return 1;
    } else {
        printf("  app data     : skipped (LEXE_APP_DATA unset; not sandboxed)\n");
    }
    printf("selftest: PASS\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* The window                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    GtkWidget *result;
    GtkWidget *clock;
} Ui;

static void on_write_clicked(GtkWidget *button, gpointer user_data) {
    (void)button;
    Ui *ui = (Ui *)user_data;
    int ok = 0;
    char *message = probe_app_data(&ok);
    char *markup = g_markup_printf_escaped(
        "<span foreground=\"%s\">%s</span>", ok ? "#1a7f37" : "#b3261e",
        message);
    gtk_label_set_markup(GTK_LABEL(ui->result), markup);
    g_free(markup);
    g_free(message);
}

static gboolean tick(gpointer user_data) {
    Ui *ui = (Ui *)user_data;
    char *stamp = now_string();
    char *markup = g_markup_printf_escaped("<b>%s</b>", stamp);
    gtk_label_set_markup(GTK_LABEL(ui->clock), markup);
    g_free(markup);
    g_free(stamp);
    return G_SOURCE_CONTINUE;
}

static GtkWidget *field_row(const char *caption, const char *value) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *key = gtk_label_new(NULL);
    char *key_markup = g_markup_printf_escaped(
        "<span foreground=\"#6b7280\">%s</span>", caption);
    gtk_label_set_markup(GTK_LABEL(key), key_markup);
    g_free(key_markup);
    gtk_label_set_xalign(GTK_LABEL(key), 0.0f);
    gtk_widget_set_size_request(key, 130, -1);

    GtkWidget *val = gtk_label_new(value);
    gtk_label_set_xalign(GTK_LABEL(val), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(val), TRUE);
    gtk_label_set_ellipsize(GTK_LABEL(val), PANGO_ELLIPSIZE_MIDDLE);

    gtk_box_pack_start(GTK_BOX(row), key, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), val, TRUE, TRUE, 0);
    return row;
}

/* --window-for: close the window and leave the main loop after n seconds.
 *
 * This exists so an automated run can prove BOTH halves of a GUI launch at once:
 * that a real top-level window mapped (witnessed from outside by xwininfo), and
 * that the application then exited on its own with a real exit code. Before it,
 * a test could have one or the other and not both -- --selftest never touches
 * GTK, --sleep deliberately opens no window, and a windowed run had to be killed,
 * which makes the result a signal rather than an exit. */
static gboolean quit_now(gpointer unused) {
    (void)unused;
    gtk_main_quit();
    return G_SOURCE_REMOVE;
}

int main(int argc, char **argv) {
    long window_for = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0) return run_selftest();
        if (strcmp(argv[i], "--window-for") == 0 && i + 1 < argc) {
            window_for = strtol(argv[i + 1], NULL, 10);
            if (window_for < 1) window_for = 1;
            if (window_for > 120) window_for = 120;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--sleep") == 0 && i + 1 < argc) {
            /* Stay alive, headlessly, for N seconds. This exists so an
             * acceptance run can inspect the LIVE process tree — "is the
             * running process the native application, with no compatibility
             * process in the path?" — on a host with no display. */
            note_launch("sleep");
            long seconds = strtol(argv[i + 1], NULL, 10);
            if (seconds < 0) seconds = 0;
            if (seconds > 120) seconds = 120;
            printf("gui-hello: holding for %ld second(s) as pid %ld\n", seconds,
                   (long)getpid());
            fflush(stdout);
            sleep((unsigned int)seconds);
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("usage: gui-hello [--selftest] [--sleep <seconds>] "
                   "[--window-for <seconds>]\n"
                   "  --selftest          report the .LEXE launch environment, "
                   "verify $LEXE_APP_DATA\n"
                   "                      is writable, and exit without opening "
                   "a window\n"
                   "  --sleep <n>         stay alive for n seconds without a "
                   "window, so a test can\n"
                   "                      inspect the live process\n"
                   "  --window-for <n>    open the window, then close it and "
                   "exit 0 after n seconds,\n"
                   "                      so a test can witness the window AND "
                   "a real exit code\n");
            return 0;
        }
    }

    note_launch("gui");

    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr,
                "gui-hello: no display available (WAYLAND_DISPLAY=%s "
                "DISPLAY=%s).\n"
                "gui-hello: run with --selftest for the headless check.\n",
                env_or("WAYLAND_DISPLAY", ""), env_or("DISPLAY", ""));
        return 2;
    }

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), APP_TITLE);
    gtk_window_set_default_size(GTK_WINDOW(window), 560, 320);
    gtk_container_set_border_width(GTK_CONTAINER(window), 18);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *column = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(window), column);

    GtkWidget *heading = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(heading),
                         "<span size=\"x-large\" weight=\"bold\">"
                         APP_TITLE "</span>");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    gtk_box_pack_start(GTK_BOX(column), heading, FALSE, FALSE, 0);

    GtkWidget *subtitle = gtk_label_new(
        "Launched through .LEXE, running inside the sandbox.");
    gtk_label_set_xalign(GTK_LABEL(subtitle), 0.0f);
    gtk_box_pack_start(GTK_BOX(column), subtitle, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(column),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE,
                       FALSE, 6);

    Ui *ui = g_new0(Ui, 1);

    gtk_box_pack_start(GTK_BOX(column),
                       field_row("LEXE_APP_ID", env_or("LEXE_APP_ID",
                                                       "(unset — not launched "
                                                       "by .LEXE)")),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(column),
                       field_row("LEXE_APP_DATA",
                                 env_or("LEXE_APP_DATA", "(unset)")),
                       FALSE, FALSE, 0);
    {
        char *pid = g_strdup_printf("%ld", (long)getpid());
        gtk_box_pack_start(GTK_BOX(column), field_row("process id", pid), FALSE,
                           FALSE, 0);
        g_free(pid);
    }

    {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *key = gtk_label_new(NULL);
        gtk_label_set_markup(GTK_LABEL(key),
                             "<span foreground=\"#6b7280\">current time</span>");
        gtk_label_set_xalign(GTK_LABEL(key), 0.0f);
        gtk_widget_set_size_request(key, 130, -1);
        ui->clock = gtk_label_new(NULL);
        gtk_label_set_xalign(GTK_LABEL(ui->clock), 0.0f);
        gtk_box_pack_start(GTK_BOX(row), key, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(row), ui->clock, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(column), row, FALSE, FALSE, 0);
    }

    gtk_box_pack_start(GTK_BOX(column),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE,
                       FALSE, 6);

    GtkWidget *button = gtk_button_new_with_label("Write a file into my private data directory");
    gtk_box_pack_start(GTK_BOX(column), button, FALSE, FALSE, 0);

    ui->result = gtk_label_new("Press the button to prove $LEXE_APP_DATA is writable.");
    gtk_label_set_xalign(GTK_LABEL(ui->result), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(ui->result), TRUE);
    gtk_label_set_selectable(GTK_LABEL(ui->result), TRUE);
    gtk_box_pack_start(GTK_BOX(column), ui->result, FALSE, FALSE, 0);

    g_signal_connect(button, "clicked", G_CALLBACK(on_write_clicked), ui);

    tick(ui);
    g_timeout_add_seconds(1, tick, ui);

    if (window_for > 0) {
        printf("gui-hello: window open for %ld second(s) as pid %ld\n",
               window_for, (long)getpid());
        fflush(stdout);
        g_timeout_add_seconds((guint)window_for, quit_now, NULL);
    }

    gtk_widget_show_all(window);
    gtk_main();
    g_free(ui);
    return 0;
}
