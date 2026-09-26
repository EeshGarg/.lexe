# windows-hello example — a Windows PE payload, cross-compiled with MinGW.
# Output lands in payload/bin/ so the folder is a ready `lexe build` project
# (lexe.json + payload/).
#
#   make            build payload/bin/windows-hello.exe   (needs mingw-w64)
#   make run        run it through Wine directly, outside .LEXE
#   make clean
#
# Debian/Ubuntu: apt install gcc-mingw-w64-x86-64 wine64
# Fedora:        dnf install mingw64-gcc wine
# Deliberately NOT `CC`: make defines CC as `cc` implicitly, and `CC ?=` will
# not override a built-in — the build would silently produce a Linux binary
# named .exe, which is precisely what the payload-role stage exists to catch.
MINGW_CC ?= x86_64-w64-mingw32-gcc
CFLAGS   ?= -O2 -Wall -Wextra
BIN := payload/bin/windows-hello.exe

all: $(BIN)

$(BIN): src/main.c
	mkdir -p payload/bin
	$(MINGW_CC) $(CFLAGS) -o $@ $<

# Outside .LEXE, for comparison: the same binary, no sandbox, no verification.
run: $(BIN)
	wine ./$(BIN) --selftest

clean:
	rm -rf payload

.PHONY: all run clean
