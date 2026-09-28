# A sub-make. It knows nothing about the directory above it and produces exactly
# one object, which the top-level link consumes. CC is inherited through the
# environment that $(MAKE) sets up, which is the part of recursive make that
# breaks when a recipe calls `make` instead of `$(MAKE)`.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

all: core.o

core.o: core.c core.h
	$(CC) $(CFLAGS) -c -o $@ core.c

clean:
	rm -f core.o

.PHONY: all clean
