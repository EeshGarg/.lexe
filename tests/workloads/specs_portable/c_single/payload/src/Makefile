# The recipe the destination machine runs. `build.system: "make"` means the
# runtime invokes `make -C <sourceDir>`, so every path here is relative to THIS
# directory and the product lands where the manifest says the entrypoint is:
# payload/bin/portable-c-single.
#
# CC is left overridable (`CC ?=`) because that is what an ordinary Makefile
# does, and a recipe that hardcodes /usr/bin/gcc is a recipe that has assumed
# something about a machine it has never seen.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable-c-single

all: $(TARGET)

$(TARGET): main.c
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ main.c

clean:
	rm -rf $(BINDIR)

.PHONY: all clean
