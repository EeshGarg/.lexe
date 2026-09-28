# An ordinary build that also leaves intermediate rubbish in the source
# directory, which is what every build does. build-stamp.txt and main.o are
# produced by this recipe and belong to the build, not to the installation.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable-hygiene

all: $(TARGET)

build-stamp.txt:
	echo "this stamp is a build artefact and must not be installed" > $@

main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ main.c

$(TARGET): main.o build-stamp.txt
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ main.o

clean:
	rm -f main.o build-stamp.txt
	rm -rf $(BINDIR)

.PHONY: all clean
