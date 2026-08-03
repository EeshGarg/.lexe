/*
 * gtk-app — a minimal GTK 3 desktop application, packaged as a .lexe.
 *
 * This example shows how to package a graphical application and where the Tux32
 * Core 1 boundary is. Core 1 is a headless/terminal contract in this Alpha (GUI
 * forwarding into the sandbox is a later milestone), so a GTK app is not meant to
 * run under the sandbox yet. Built on a current host it is also non-conformant on
 * the symbol axis (it imports newer glibc symbols), which `lexe sdk verify`
 * reports. Note too that GTK loads its graphics stack with dlopen, so those
 * host-driver dependencies are not visible in static ELF metadata — a documented
 * Core 1 limitation. Use this to see the boundary, not as a sandbox-runnable app.
 */
#include <gtk/gtk.h>

int main(int argc, char **argv) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Lexe GTK Example");
    gtk_window_set_default_size(GTK_WINDOW(window), 360, 140);
    gtk_container_set_border_width(GTK_CONTAINER(window), 16);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *label =
        gtk_label_new("Hello from a .lexe GTK application!");
    gtk_container_add(GTK_CONTAINER(window), label);

    gtk_widget_show_all(window);
    gtk_main();
    return 0;
}
