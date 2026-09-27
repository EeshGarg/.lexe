# The objects are listed in an order that guarantees two of them are built before
# the failure. `make` stops at the first failing recipe by default, which is the
# behaviour under test: a partially built tree, no product, and a non-zero exit.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
OBJS     = first.o second.o third_broken.o main.o
TARGET   = $(BINDIR)/portable-build-fails-partway

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

first.o: first.c
	$(CC) $(CFLAGS) -c -o $@ $<

second.o: second.c
	$(CC) $(CFLAGS) -c -o $@ $<

third_broken.o: third_broken.c
	$(CC) $(CFLAGS) -c -o $@ $<

main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: all
