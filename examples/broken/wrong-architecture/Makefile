# Deliberately builds for the HOST while lexe.json declares only aarch64, which
# is what a cross-compiling script does when it silently falls back to `cc`.
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra
all: payload/bin/app
payload/bin/app: src/main.c
	mkdir -p payload/bin
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -rf payload
.PHONY: all clean
