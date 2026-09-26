# The build recipe .LEXE runs on the DESTINATION machine, inside the sandbox
# (unprivileged, network denied, no display). Its working directory is the
# payload root, and `build.system: "make"` invokes it as `make -C src`, so the
# output path below is relative to this directory.
#
# It must produce exactly the file the manifest declares as the entrypoint —
# payload/bin/portable-hello — and nothing else is promoted.
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra

all: ../bin/portable-hello

../bin/portable-hello: main.c
	mkdir -p ../bin
	$(CC) $(CFLAGS) -o $@ main.c

.PHONY: all
