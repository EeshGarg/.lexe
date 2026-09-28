# Four objects with no dependency on each other and one link that needs all
# four. Under -j they are compiled concurrently; under plain make they are
# compiled in list order. The product must be identical either way, and the
# prerequisites are written out in full so that it is -- a rule that relied on
# the order make happens to use is the classic parallel-build bug, and it is
# invisible until somebody passes -j.
#
# report-flags exists because a correct product does NOT show that -j arrived.
# Three specimens share this file: one run with MAKEFLAGS=-j4 in the
# environment, one run as `make -j4` from a declared argv, and one run plain --
# and without this rule all three would be identical records and the property
# would be undeclarable.
#
# The test is written in the RECIPE, in shell, and that detail was learned the
# hard way. The first version asked at parse time:
#
#     ifneq (,$(findstring j,$(MAKEFLAGS)))     # WRONG
#
# and reported "no" for a build make had been given -j4. GNU make appends -j and
# --jobserver-auth to MAKEFLAGS AFTER it has finished reading the makefiles, so
# at parse time MAKEFLAGS held only `w` (the --print-directory that -C implies).
# Expanded inside a recipe line the same variable reads
# `w -j4 --jobserver-auth=3,4`. Any makefile that changes its own behaviour
# based on a parse-time look at MAKEFLAGS is deciding on stale information.
#
# The case pattern matches " -j" with a leading space rather than a bare "-j",
# so that the "--jobserver-auth" that accompanies it cannot match on its own.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
BINDIR   = ../bin
OBJS     = part0.o part1.o part2.o part3.o
TARGET   = $(BINDIR)/portable-parallel

all: report-flags $(TARGET)

report-flags:
	@echo "OBS_PORTABLE_MAKEFLAGS=[$(MAKEFLAGS)]"
	@case " $(MAKEFLAGS)" in \
	  *" -j"*) echo "PORTABLE_PARALLEL_SEEN=yes" ;; \
	  *)       echo "PORTABLE_PARALLEL_SEEN=no"  ;; \
	esac

part0.o: part0.c parts.h
	$(CC) $(CFLAGS) -c -o $@ part0.c
part1.o: part1.c parts.h
	$(CC) $(CFLAGS) -c -o $@ part1.c
part2.o: part2.c parts.h
	$(CC) $(CFLAGS) -c -o $@ part2.c
part3.o: part3.c parts.h
	$(CC) $(CFLAGS) -c -o $@ part3.c

$(TARGET): main.c parts.h $(OBJS)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ main.c $(OBJS)

clean:
	rm -f $(OBJS)
	rm -rf $(BINDIR)

.PHONY: all clean report-flags
