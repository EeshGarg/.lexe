# A C++ recipe. CXX rather than CC, -pthread for std::thread, and the C++
# standard asked for explicitly: a recipe that relies on the host compiler's
# default standard is a recipe that builds differently on two machines.
CXX      ?= c++
CXXFLAGS ?= -O2 -std=gnu++17 -Wall -Wextra
LDFLAGS  ?= -pthread
BINDIR    = ../bin
TARGET    = $(BINDIR)/portable-cxx

all: $(TARGET)

$(TARGET): main.cpp
	mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) -o $@ main.cpp $(LDFLAGS)

clean:
	rm -rf $(BINDIR)

.PHONY: all clean
