CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

all: util.o

util.o: util.c util.h
	$(CC) $(CFLAGS) -c -o $@ util.c

clean:
	rm -f util.o

.PHONY: all clean
