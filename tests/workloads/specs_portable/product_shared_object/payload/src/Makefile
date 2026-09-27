# -shared, where an executable was meant. Everything else about this recipe is
# ordinary, which is the point: the build system reports success, the file
# appears at the declared path, and nothing before the first launch attempt has
# any reason to complain.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable-product-shared-object

all: $(TARGET)

$(TARGET): main.c
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -shared -o $@ main.c

.PHONY: all
