# Two compilers in one build. The C file must be compiled by $(CC) and the C++
# file by $(CXX), and the LINK must be driven by $(CXX): a link driven by cc
# produces undefined references to the C++ runtime, which is the failure this
# recipe exists to not have.
CC      ?= cc
CXX     ?= c++
CFLAGS  ?= -O2 -Wall -Wextra
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable-mixed-c-cxx

all: $(TARGET)

cpart.o: cpart.c cpart.h
	$(CC) $(CFLAGS) -c -o $@ cpart.c

main.o: main.cpp cpart.h
	$(CXX) $(CXXFLAGS) -c -o $@ main.cpp

$(TARGET): main.o cpart.o
	mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) -o $@ main.o cpart.o

clean:
	rm -f cpart.o main.o
	rm -rf $(BINDIR)

.PHONY: all clean
