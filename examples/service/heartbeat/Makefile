# heartbeat example — a `launch.mode: "service"` application.
#
#   make            build payload/bin/heartbeat
#   make clean
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra
BIN := payload/bin/heartbeat

all: $(BIN)

$(BIN): src/main.c
	mkdir -p payload/bin
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf payload

.PHONY: all clean
