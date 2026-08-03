# gtk-app example — a minimal GTK 3 desktop application. Builds into payload/bin/
# so the folder is a ready `lexe build` project. Requires the GTK 3 development
# package (see ../README.md and the top-level Quick install).
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra -march=x86-64
GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS   := $(shell pkg-config --libs gtk+-3.0)
BIN := payload/bin/gtk-example

$(BIN): src/main.c
	mkdir -p payload/bin
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ $< $(GTK_LIBS)

clean:
	rm -f $(BIN)

.PHONY: clean
