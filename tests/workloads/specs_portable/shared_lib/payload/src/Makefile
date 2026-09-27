# A build that produces a shared library and a program linked against it, both
# installed into the payload, with the program able to find the library wherever
# the payload ends up.
#
# The rpath here is the CORRECT idiom: a literal $ORIGIN, which the dynamic
# loader expands at run time to the directory holding the binary. Getting it
# into the link line takes two levels of quoting -- $$ for make, single quotes
# for the shell -- and getting that wrong is the whole subject of the
# portable-rpath-* specimens next door.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC
BINDIR   = ../bin
LIBDIR   = ../lib
LIB      = $(LIBDIR)/libutil.so
APP      = $(BINDIR)/portable-shared-lib

all: $(APP)

$(LIB): libutil.c libutil.h
	mkdir -p $(LIBDIR)
	$(CC) $(CFLAGS) -shared -o $@ libutil.c

$(APP): app.c libutil.h $(LIB)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ app.c -L$(LIBDIR) -lutil -Wl,-rpath,'$$ORIGIN/../lib'

clean:
	rm -rf $(BINDIR) $(LIBDIR)

.PHONY: all clean
