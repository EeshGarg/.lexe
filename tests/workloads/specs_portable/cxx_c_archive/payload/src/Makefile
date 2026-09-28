# cc compiles, ar archives, c++ links. Three declared tools, one product.
CC      ?= cc
CXX     ?= c++
AR      ?= ar
CFLAGS  ?= -O2 -Wall -Wextra
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17
BINDIR   = ../bin
LIBDIR   = ../lib
LIB      = $(LIBDIR)/libclib.a
TARGET   = $(BINDIR)/portable-cxx-c-archive

all: $(TARGET)

clib.o: clib.c clib.h
	$(CC) $(CFLAGS) -c -o $@ clib.c

$(LIB): clib.o
	mkdir -p $(LIBDIR)
	$(AR) rcs $@ clib.o

$(TARGET): main.cpp clib.h $(LIB)
	mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) -o $@ main.cpp -L$(LIBDIR) -lclib

clean:
	rm -f clib.o
	rm -rf $(BINDIR) $(LIBDIR)

.PHONY: all clean
