# A static library and its consumer, in that order, from one build.
#
# `ar` is a declared tool of its own: it is not the compiler, it is not the
# linker, and a host with cc and make but no binutils ar cannot run this recipe.
CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
LIBDIR   = ../lib
LIB      = $(LIBDIR)/libutil.a
TARGET   = $(BINDIR)/portable-static-lib

all: $(TARGET)

util.o: util.c util.h
	$(CC) $(CFLAGS) -c -o $@ util.c

$(LIB): util.o
	mkdir -p $(LIBDIR)
	$(AR) rcs $@ util.o

$(TARGET): main.c util.h $(LIB)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ main.c -L$(LIBDIR) -lutil

clean:
	rm -f util.o
	rm -rf $(BINDIR) $(LIBDIR)

.PHONY: all clean
