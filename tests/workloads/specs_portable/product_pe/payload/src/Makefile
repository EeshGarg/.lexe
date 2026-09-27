# The cross compiler is named explicitly and declared in build.toolchain, so a
# host without it reports a missing tool rather than silently building a native
# binary instead. The product lands at exactly the path the manifest declares as
# the entrypoint -- no .exe suffix, because the manifest does not say .exe and
# what matters here is the FORMAT of the file at the declared path, not its name.
CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -Wextra
BINDIR  = ../bin
TARGET  = $(BINDIR)/portable-product-pe

all: $(TARGET)

$(TARGET): main.c
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -static -o $@ main.c

.PHONY: all
