# .lexe

.lexe is a file format that enables the titular double click to execute program feature from windows on linux.

> Download. Double-click. Verify. Install. Launch.

A `.lexe` file is a self-describing application package or launcher. The Lexe Runtime opens it, verifies publisher signatures and payload hashes, shows the user exactly what they are trusting — publisher, permissions, source, disk usage, update policy — and installs it into userspace. No package managers, repositories, Wine prefixes, or desktop entries to understand.

## Documentation

* [SPEC.md](SPEC.md) — full format and runtime specification, including the Lexe 0.1 → 0.3 roadmap.

## Status

The specification is drafted. The reference Lexe Runtime is implemented in modern C++; the specification itself is language-neutral, and compatible third-party runtimes may be implemented in any language.

## License

[Apache-2.0](LICENSE)
