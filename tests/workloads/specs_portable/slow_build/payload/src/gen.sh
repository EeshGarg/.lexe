#!/bin/sh
# Generates the bulk of the program at build time. Two reasons this is not a
# `sleep`:
#
#   * a sleep is not a build. What makes a slow build interesting is that it
#     occupies a compiler, allocates memory, and writes intermediate files --
#     all of which a sandbox with limits has an opinion about, and a sleep
#     exercises none of it;
#   * it is a real thing recipes do. Generated sources, a parser generator, a
#     table baked from a data file: the build produces its own inputs first, and
#     anything that assumes the source tree is what shipped gets this wrong.
#
# Deterministic: the same UNITS always produces byte-identical output.
set -eu
units="$1"
out="$2"

{
    echo '/* GENERATED at build time by gen.sh -- do not edit. */'
    echo '#include "generated.h"'
    echo
    i=0
    while [ "$i" -lt "$units" ]; do
        echo "unsigned long gen_fn_$i(unsigned long x) {"
        j=0
        while [ "$j" -lt 24 ]; do
            echo "    x = (x * 16777619UL + ${i}UL + ${j}UL) & 0xffffffffUL; x ^= x >> 13;"
            j=$((j + 1))
        done
        echo "    return x;"
        echo '}'
        i=$((i + 1))
    done
    echo
    echo 'unsigned long gen_all(unsigned long x) {'
    i=0
    while [ "$i" -lt "$units" ]; do
        echo "    x = gen_fn_$i(x);"
        i=$((i + 1))
    done
    echo '    return x;'
    echo '}'
} > "$out"

{
    echo '#ifndef GENERATED_H'
    echo '#define GENERATED_H'
    i=0
    while [ "$i" -lt "$units" ]; do
        echo "unsigned long gen_fn_$i(unsigned long x);"
        i=$((i + 1))
    done
    echo 'unsigned long gen_all(unsigned long x);'
    echo '#define GEN_UNITS' " $units"
    echo '#endif'
} > "$(dirname "$out")/generated.h"
