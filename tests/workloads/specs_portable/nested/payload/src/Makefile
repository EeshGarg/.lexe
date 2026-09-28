# One Makefile at the top of a tree, sources three levels down. Paths are written
# out rather than swept up with a wildcard or a `find`, because a wildcard over a
# tree is how a stale object from a previous build gets linked in.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
OBJS     = module/deep/leaf.o
TARGET   = $(BINDIR)/portable-nested-layout

all: $(TARGET)

module/deep/leaf.o: module/deep/leaf.c module/deep/leaf.h
	$(CC) $(CFLAGS) -c -o $@ module/deep/leaf.c

$(TARGET): main.c $(OBJS)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -I. -o $@ main.c $(OBJS)

clean:
	rm -f $(OBJS)
	rm -rf $(BINDIR)

.PHONY: all clean
