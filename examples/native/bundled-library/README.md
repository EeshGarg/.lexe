# Example: bundled-library

An application that ships its **own** shared library inside the package. This is
the common real-world case the dependency engine is built for: `libgreeting.so`
is not a system library, so it must travel *with* the app.

`make` produces:

```
payload/bin/greeter          the executable (RPATH $ORIGIN/../lib)
payload/lib/libgreeting.so   its bundled library
```

`lexe analyze .` classifies `libgreeting.so` as a **bundle** dependency (carried
in the payload) while `libc` stays **host-provided** — which is exactly what
makes the package self-contained and portable:

```sh
make
lexe analyze .              # libgreeting.so -> bundle; libc.so.6 -> host
lexe sdk verify .           # Tux32 Core 1 verdict
lexe build . -o greeter.lexe --key key.json
lexe run org.lexe.examples.bundled-library
#   Hello from a bundled shared library!
```
