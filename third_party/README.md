# Vendored third-party libraries

Pinned, vendored, and never modified (compile-time configuration only, e.g.
`MINIZ_NO_TIME`). See `docs/ARCHITECTURE.md` §Third-party.

| Library | Version | Files | License | Purpose |
|---|---|---|---|---|
| nlohmann/json | 3.11.3 | `nlohmann/json.hpp` | MIT | JSON parsing/serialization |
| miniz | 3.0.2 (amalgamated, `MZ_VERSION` "11.0.2") | `miniz/miniz.h`, `miniz/miniz.c` | MIT | ZIP read/write |
| orlp/ed25519 | master snapshot (vendored 2026-07-13) | `ed25519/*.h`, `ed25519/*.c` | zlib | Ed25519 **fallback** signer + test key-derivation |
| PicoSHA2 | master snapshot (vendored 2026-07-13) | `picosha2/picosha2.h` | MIT | SHA-256 |
| doctest | 2.4.11 | `doctest/doctest.h` | MIT | unit tests |

## Ed25519 crypto provider

The primary Ed25519 provider is **libsodium** (a maintained library), used for
all signing and verification when available. It is NOT vendored — it is found
at build time via `pkg-config` (`libsodium`) and linked dynamically, so it is a
**runtime dependency** on Linux (`libsodium23` / `libsodium-dev`; present in the
standard repositories of every supported distribution). When libsodium is not
found (currently the MSVC dev host, which has no pkg-config/libsodium), the
build falls back to the vendored `orlp/ed25519` with the runtime's own strict
canonical-`S` and canonical/degenerate-key checks. Both providers implement
standard Ed25519 (RFC 8032), so packages are byte-for-byte compatible across
them (proven by cross-provider fixtures in `tests/test_ed25519_strict.cpp`).
libsodium's `crypto_sign_ed25519_verify_detached` additionally rejects
non-canonical `S` and small-order / non-canonical point encodings per its
documented API.

## Exact upstream sources

### nlohmann/json 3.11.3 (MIT)
* https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
  -> `nlohmann/json.hpp`
* License: MIT — https://github.com/nlohmann/json/blob/v3.11.3/LICENSE.MIT

### miniz 3.0.2 (MIT)
* https://github.com/richgel999/miniz/releases/download/3.0.2/miniz-3.0.2.zip
  -> extracted `miniz.h` and `miniz.c` only -> `miniz/`
* License: MIT — `LICENSE` inside the release archive,
  https://github.com/richgel999/miniz/blob/3.0.2/LICENSE
* Compiled with `MINIZ_NO_TIME` (deterministic archives, FORMAT-0.1 §1).

### orlp/ed25519 master snapshot (zlib)
* https://raw.githubusercontent.com/orlp/ed25519/master/src/`<file>` for each of:
  `ed25519.h fixedint.h fe.h fe.c ge.h ge.c sc.h sc.c sha512.h sha512.c
  precomp_data.h keypair.c sign.c verify.c seed.c add_scalar.c key_exchange.c`
  -> `ed25519/`
* Fetched 2026-07-13 from the `master` branch (upstream is unversioned/stable).
* License: zlib — https://github.com/orlp/ed25519/blob/master/license.txt

### PicoSHA2 master snapshot (MIT)
* https://raw.githubusercontent.com/okdshin/PicoSHA2/master/picosha2.h
  -> `picosha2/picosha2.h`
* Fetched 2026-07-13 from the `master` branch.
* License: MIT — header of `picosha2.h`,
  https://github.com/okdshin/PicoSHA2/blob/master/LICENSE

### doctest 2.4.11 (MIT)
* https://raw.githubusercontent.com/doctest/doctest/v2.4.11/doctest/doctest.h
  -> `doctest/doctest.h`
* License: MIT — https://github.com/doctest/doctest/blob/v2.4.11/LICENSE.txt
