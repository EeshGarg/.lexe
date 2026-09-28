# Three executables and one shared object list. A package is not required to
# produce exactly one program, and a manifest names exactly one entrypoint -- so
# the other two are products that an install has to carry even though nothing
# ever launches them through the manifest.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
PROGS    = $(BINDIR)/portable-multi-alpha \
           $(BINDIR)/portable-multi-beta \
           $(BINDIR)/portable-multi-gamma

all: $(PROGS)

common.o: common.c common.h
	$(CC) $(CFLAGS) -c -o $@ common.c

$(BINDIR)/portable-multi-%: main_%.c common.o common.h
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $< common.o

clean:
	rm -f common.o
	rm -rf $(BINDIR)

.PHONY: all clean
