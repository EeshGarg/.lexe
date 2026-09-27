# Four translation units, compiled separately and linked. Object files are named
# explicitly rather than swept up with a wildcard, because a wildcard is how a
# stale object from a previous build gets linked into this one.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
OBJS     = util.o calc.o report.o main.o
TARGET   = $(BINDIR)/portable-c-multi-tu

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c common.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS)
	rm -rf $(BINDIR)

.PHONY: all clean
