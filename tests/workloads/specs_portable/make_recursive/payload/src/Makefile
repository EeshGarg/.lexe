# Recursive make: the top level builds nothing itself until two sub-makes have
# run. `$(MAKE)` rather than `make` on purpose -- $(MAKE) carries the jobserver
# and the command-line variables into the sub-make, and a recipe that writes
# `make` loses both and then behaves differently under -j than without it.
#
# The sub-directories are also what makes this package's sourceDir a TREE rather
# than a flat list of files, which is the other half of the property.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
SUBDIRS  = core util
OBJS     = core/core.o util/util.o
TARGET   = $(BINDIR)/portable-make-recursive

all: $(TARGET)

subdirs:
	$(MAKE) -C core
	$(MAKE) -C util

$(TARGET): main.c subdirs
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -Icore -Iutil -o $@ main.c $(OBJS)

clean:
	$(MAKE) -C core clean
	$(MAKE) -C util clean
	rm -rf $(BINDIR)

.PHONY: all clean subdirs
