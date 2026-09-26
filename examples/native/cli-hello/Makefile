# cli-tool example — dynamically linked C CLI, links libm. Output lands in
# payload/bin/ so the folder is a ready `lexe build` project (lexe.json +
# payload/). Build in the Core 1 sysroot for a Core Portable package.
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra -march=x86-64
LDLIBS := -lm
BIN := payload/bin/cli-tool

$(BIN): src/main.c
	mkdir -p payload/bin
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(BIN)

.PHONY: clean
