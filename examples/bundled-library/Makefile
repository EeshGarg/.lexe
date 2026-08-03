# bundled-library example — an executable plus its OWN shared library, both
# carried inside the package. libgreeting.so lands in payload/lib and the
# executable in payload/bin; an RPATH of $ORIGIN/../lib loads the library from
# the payload at runtime. `lexe analyze` then classifies libgreeting.so as a
# "bundle" dependency (carried in the package), while libc stays host-provided.
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra -march=x86-64 -Isrc
LIB := payload/lib/libgreeting.so
BIN := payload/bin/greeter

all: $(BIN)

$(LIB): src/greeting.c src/greeting.h
	mkdir -p payload/lib
	$(CC) $(CFLAGS) -fPIC -shared -Wl,-soname,libgreeting.so -o $@ src/greeting.c

$(BIN): src/main.c $(LIB)
	mkdir -p payload/bin
	$(CC) $(CFLAGS) -o $@ src/main.c -Lpayload/lib -lgreeting \
	      -Wl,-rpath,'$$ORIGIN/../lib'

clean:
	rm -f $(BIN) $(LIB)

.PHONY: all clean
