# Tux32 Core 1 reference app. Dynamically linked, links libm (-lm), built at
# the x86-64-v1 CPU baseline. The binary lands in payload/bin/ so the folder is
# a ready `lexe build` project (lexe.json + payload/).
#
# For a CONFORMANT build, compile in the Core 1 sysroot:
#   ../build-in-sysroot.sh . && lexe sdk verify .
# A build on a host with glibc newer than 2.31 will exceed the ceiling and be
# rejected by `lexe sdk verify` — that rejection is the point.
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra -march=x86-64
LDLIBS := -lm

BIN := payload/bin/portable-probe

$(BIN): src/portable_probe.c
	mkdir -p payload/bin
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(BIN)

.PHONY: clean
