# One product, launched fourteen different ways. Nothing here is special: the
# variation in this family is entirely in `entrypoint.arguments` in each
# manifest, which is the one part of the manifest no other recipe exercises.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable-run

all: $(TARGET)

$(TARGET): main.c
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ main.c

clean:
	rm -rf $(BINDIR)

.PHONY: all clean
