# An ordinary recipe. Nothing here asks for a large product; the product is
# large because of one initialiser in main.c, which is exactly how this happens
# to people.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable-large-product

all: $(TARGET)

$(TARGET): main.c
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ main.c

clean:
	rm -rf $(BINDIR)

.PHONY: all clean
