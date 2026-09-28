# Configure, then compile. config.h does not exist in the shipped package and is
# a prerequisite of the object, so make has to run the generator first -- and a
# consumer that copies only the *.c files, or that compiles main.c directly
# without running the recipe, gets a missing-header failure.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
SH      ?= /bin/sh
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable-configure-step

all: $(TARGET)

config.h: configure.sh
	$(SH) configure.sh config.h

$(TARGET): main.c config.h
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -I. -o $@ main.c

clean:
	rm -f config.h
	rm -rf $(BINDIR)

.PHONY: all clean
