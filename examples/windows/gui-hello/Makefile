# windows-gui example — a Windows GUI PE payload, cross-compiled with MinGW.
#
# The console example (../windows-hello) proves a foreign-OS PROCESS runs. This
# one proves a foreign-OS WINDOW appears: it is a real Win32 GUI program with a
# message loop, and it is the payload the Wine and Proton GUI acceptance checks
# use to show that a window actually mapped on a display rather than that a
# process was created.
#
#   make            build payload/bin/windows-gui.exe   (needs mingw-w64)
#   make run        run it through Wine directly, outside .LEXE
#   make clean
#
# Debian/Ubuntu: apt install gcc-mingw-w64-x86-64 wine64
# Fedora:        dnf install mingw64-gcc wine
#
# Deliberately NOT `CC`: make defines CC as `cc` implicitly and `CC ?=` will not
# override a built-in, so the build would silently produce a Linux binary named
# .exe — which is exactly what the payload-role verification stage exists to
# catch, and not a thing this example should be demonstrating by accident.
MINGW_CC ?= x86_64-w64-mingw32-gcc
CFLAGS   ?= -O2 -Wall -Wextra
# -mwindows makes it a GUI subsystem image: no console is allocated, which is
# what distinguishes this from ../windows-hello at the PE header level and what
# `lexe inspect` reports as the subsystem.
LDFLAGS  ?= -mwindows
BIN := payload/bin/windows-gui.exe

all: $(BIN)

$(BIN): src/main.c
	mkdir -p payload/bin
	$(MINGW_CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Outside .LEXE, for comparison: the same binary, no sandbox, no verification.
run: $(BIN)
	wine ./$(BIN) --window-for 5

clean:
	rm -rf payload

.PHONY: all run clean
