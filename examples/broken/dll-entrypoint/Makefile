# Builds a DLL and declares it as the entrypoint, which the payload-role stage
# refuses: a DLL is a valid PE image but not a program.
MINGW_CC ?= x86_64-w64-mingw32-gcc
CFLAGS   ?= -O2 -Wall -Wextra
all: payload/bin/lib.dll
payload/bin/lib.dll: src/lib.c
	mkdir -p payload/bin
	$(MINGW_CC) $(CFLAGS) -shared -o $@ $<
clean:
	rm -rf payload
.PHONY: all clean
