# A make build in a directory whose name contains a space.
#
# This works, and it works only because of how it is written. GNU make separates
# targets and prerequisites with whitespace and offers no quoting that survives
# it, so `$(BINDIR)/portable path with space:` declares five targets, and
# `$(TARGET): main.c` with a space in $(TARGET) is a syntax nobody can fix.
#
# The way out is to stop naming the spaced path as a target at all: `all` is
# PHONY, it has no file prerequisites, and the only place the spaced path appears
# is inside a recipe line, where it is the SHELL doing the parsing and ordinary
# double quotes work. The cost is that the product is rebuilt unconditionally,
# because make no longer knows what file this rule produces.
#
# make -C "src with space" from the payload root is fine: that path is an
# argument to make, not a token in a makefile, so it is quoted by whoever spawns
# make and never parsed by make itself.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable path with space

all:
	mkdir -p "$(BINDIR)"
	$(CC) $(CFLAGS) -o "$(TARGET)" main.c

clean:
	rm -rf "$(BINDIR)"

.PHONY: all clean
