# A build slow enough to watch. The time goes into the compiler, not into a
# sleep: gen.sh writes a large generated translation unit, and then the compiler
# spends real seconds on it at -O2.
#
# UNITS is overridable so the same recipe can be made faster or slower without
# editing it, which is how the duration gets tuned to "observable" rather than
# "annoying".
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
SHELL_   = /bin/sh
UNITS   ?= 800
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable-slow-build

all: $(TARGET)

generated.c generated.h: gen.sh
	$(SHELL_) gen.sh $(UNITS) generated.c

$(TARGET): main.c generated.c generated.h
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -I. -o $@ main.c generated.c

clean:
	rm -f generated.c generated.h
	rm -rf $(BINDIR)

.PHONY: all clean
