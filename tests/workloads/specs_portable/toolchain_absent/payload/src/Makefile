# CC is set, not defaulted: this recipe needs THIS compiler and no other, which
# is what declaring it in build.toolchain says. `?=` would let the build quietly
# fall back to the host cc and produce something the manifest never promised.
CC      = lexe-nonexistent-cc
CFLAGS  = -O2
BINDIR  = ../bin
TARGET  = $(BINDIR)/portable-toolchain-absent

all: $(TARGET)

$(TARGET): main.c
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ main.c

.PHONY: all
