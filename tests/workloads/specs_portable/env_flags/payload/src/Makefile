# A build that reads an environment variable to choose its flags.
#
# `?=` means the environment wins and the recipe still works when nothing is
# set, which is the whole idiom: two specimens share this file, one built with
# PORTABLE_PROFILE absent and one with it set to "debug", and the difference in
# the product is a declared fact about each.
#
# Note that the profile name reaches the compiler as a -D and the flags reach it
# separately, so the product can report both what the recipe decided and what the
# compiler was actually given.
CC      ?= cc
PORTABLE_PROFILE ?= release

ifeq ($(PORTABLE_PROFILE),debug)
PROFILE_FLAGS = -O0 -g
else
PROFILE_FLAGS = -O2 -DNDEBUG
endif

CFLAGS  ?= -Wall -Wextra
BINDIR   = ../bin
TARGET   = $(BINDIR)/portable-env-flags

all: $(TARGET)

$(TARGET): main.c
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(PROFILE_FLAGS) -DPORTABLE_PROFILE='"$(PORTABLE_PROFILE)"' -o $@ main.c

clean:
	rm -rf $(BINDIR)

.PHONY: all clean
