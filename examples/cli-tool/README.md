# Example: cli-tool

A minimal `.lexe` command-line application. It reads its arguments and prints the
square root of each (using libm), so it exercises a real dynamic dependency.

```sh
make                                 # -> payload/bin/cli-tool
lexe sdk verify .                    # Tux32 Core 1 verdict
lexe build . -o cli-tool.lexe --key key.json
lexe run org.lexe.examples.cli-tool -- 2 9 16
#   sqrt(2)  = 1.414214
#   sqrt(9)  = 3.000000
#   sqrt(16) = 4.000000
```

Build it in the Core 1 sysroot (see [../README.md](../README.md)) for a
conformant, Core Portable package.
