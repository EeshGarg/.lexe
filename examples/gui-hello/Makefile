# gui-hello example — a real GTK 3 desktop application that is meant to RUN
# under the .LEXE sandbox (unlike ../gtk-app/, which exists to show the Tux32
# Core 1 boundary). Output lands in payload/bin/ so the folder is a ready
# `lexe build` project (lexe.json + payload/ + icons/).
#
#   make            build payload/bin/gui-hello   (needs GTK 3 dev headers)
#   make selftest   run the headless self-test on the host
#   make clean
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra
GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS   := $(shell pkg-config --libs gtk+-3.0)
BIN := payload/bin/gui-hello

all: $(BIN)

$(BIN): src/main.c
	mkdir -p payload/bin
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ $< $(GTK_LIBS)

selftest: $(BIN)
	./$(BIN) --selftest

clean:
	rm -rf payload

.PHONY: all clean selftest
