# Handoff — 2026-10-02, FORMAT-0.1 foundation hardening

Where .LEXE stands after the hardening campaign. Written to be read cold.
Earlier handoffs: `2c0a675` (ARM campaign), `55ad1ab`, `5bccec3`.

## Status in one paragraph

**Developer Preview: NOT READY** — unchanged, and not affected by this
campaign: the second-ISA gate needs conventional AArch64 Linux with working
user namespaces (the tablet is BLOCKED: ENVIRONMENT; see `2c0a675`'s
handoff). This campaign moved **FORMAT-0.1 Conformance** forward: two local
security bugs and five verification bugs fixed, `verify`/`inspect`/`info` now
claim only what they observed, the spec states rules that previously lived only
in code or the appendix, and the independent validator agrees with the
reference implementation on a 198-case spec-derived corpus.

## Commits

| | |
|---|---|
| **Starting HEAD** | `2c0a675` |
| **Evidence run** | `scripts/test.sh --unit --acceptance --conformance --security` from a clean tree (porcelain 0 before and after): **unit 784/784, acceptance 12/12, conformance 4/4, security 27/27**. Log: `../lexe-run-evidence/hardening-run-699a2fa.log` — the run is at **`699a2fa`**, which differs from `d5837c8` only by two test-file fixes the first two attempts exposed (a raw bidi byte in a test source, which `-Wbidi-chars` + warnings-as-failure stopped; and the launcher test below) |
| **Final HEAD** | the commit that adds this file (docs only) |
| **GitHub** | pushed; `origin/main` verified with `git ls-remote` after the push |

## Bugs found and fixed (each: regression test proven to fail first)

| # | Class | Severity | What | Fix | Regression |
|---|---|---|---|---|---|
| 1 | product security | **high** (local) | `lexe inspect` extracted into `/tmp/lexe-inspect-<sha16>`, a name the package author can compute; in sticky /tmp another user plants it as a link and the payload lands in the victim's directory | private `mkdtemp` dir — `7d276f6` | test_cli_inspect: planted link, writable and non-removable cases; old code wrote `bin/app` into the victim dir |
| 2 | product security | medium | an ELF `DT_NEEDED` of `/etc/passwd` or `../x` made `inspect` open and hash host files (existence/content oracle) | path-like sonames never looked up — `3e53c8a` | test_depengine: 6 assertions failed on old code |
| 3 | verification | high | `lexe.json`/`hashes.json` + NUL + garbage verified OK (nlohmann stops at NUL) | json_strict rejects raw NUL — `3680b42` | test_json_strict |
| 4 | verification | high | central-directory slack / an uncounted CD record verified OK (two ZIP readers, two archives) | CD must be exactly its counted records — `df0c4fd` | test_hostile_packages + corpus |
| 5 | verification | high | portable entrypoint `bin/./built` shipped a prebuilt ELF past §6.7 and verify said "no prebuilt entrypoint" | `.` segments rejected — `6cda4cc` | test_hostile_packages (entrypoint and sourceDir) + corpus |
| 6 | misleading output | high | package text forged terminal lines (`Verification: PASSED` under Name; ESC/bidi) in inspect, verify, info, install, apps, stderr, build report | `util::display_safe` — `a7895a1`, `0b25cab` | forge test on both streams; display_safe branch table |
| 7 | misleading output | medium | `inspect` gave Tux32/compatibility verdicts for packages with no analysed binary; assumed Core Portable for every package (§5.7 violation); showed a failing package's claims before the verdict | `7123511` | test_cli_inspect, 7 assertions failed on old code |
| 8 | misleading output | medium | `lexe info <file>` showed a failing package's key and claims with no verdict | `566a9b1` | negative and positive subcases |
| 9 | automation | medium | `verify --json` printed nothing (exit 1) when a detail held invalid UTF-8 | replace handler on every CLI dump — `a7895a1` | 0xFF file-name case |
| 10 | independent validator | — | accepted NaN, 1e999, `\x0b`, STORE size mismatch, truncated ELF, EOCD count mismatch, identity-point Ed25519 key, non-canonical key base64; crashed on deep JSON and lone surrogates | `0e3a1d4` | 16 corpus cases; 4 mutation proofs |

Also: `inspect --json` carries an `inventory` (every entry, size, digest
computed from stored bytes, covering mechanism) — `5956f24`. The CLI execution
observer now covers `verify`/`inspect`, human and `--json` (`7d276f6`; a
mutant that ran the entrypoint was caught).

## FORMAT / policy (`967ec7e`)

**FORMAT, now normative in the body:** whole-file archive and STORE/DEFLATE-only
for readers (§1); ZIP64 rejected (was MAY); byte comparison, no Unicode
normalization, NFC/NFD pair valid (§2.1); CD exactness (§2.2); Ed25519
strictness and canonical key text (§4, were appendix-only); RFC 8259 spelled
out, raw NUL, lone surrogates, 1e999 (§5.0); payload paths use the §2.1
grammar incl. `.` (§5.3; closes an A.7 item).

**REFERENCE POLICY §4:** what verify/inspect promise: no execution, analysis
only of a verified native binary, authenticated-first output, declared
profile, private temp dir, DT_NEEDED paths unresolved, display escaping,
always-valid JSON.

**OPEN (Appendix A.7), deliberately not decided:** Unicode-normalization
aliasing; file/directory prefix conflicts (`payload/bin` + `payload/bin/app`,
accepted by both implementations, unextractable); unsigned bytes inside
records (comments, extra fields, post-DEFLATE slack — SHA-256 malleable,
covert channel); control characters in `name`; `updates.manifest` scheme at
verify time; launch references for a stateless validator; `integration`
members. Also: the execution-chain layer-order question already there.

## Evidence

* Evidence run at `699a2fa` (above): 784 unit cases, 12 acceptance scripts, 4 conformance scripts (01 differential, 02 gate agreement, 03 corpus, 04 update corpus), 27 security checks — all PASS, 0 skipped, 0 blocked.
* The first evidence attempt (`d5837c8`) failed at build (raw U+202E in a test source); the second (`6f2e5cf`) found unit 783/784: a launcher test whose premise — "`.` passes every §5 lexical rule" — this campaign's `.`-segment rule had made false. It now asserts the refusal at the manifest (`699a2fa`). Consequence: on a host without symlink support nothing reaches the launcher's containment branch any more.

Conformance lane 03 (validator agent, and again in the evidence run above): 198 cases — 40 accept, 158 reject, 0 unspecified —
C++ and the independent validator agree on every case and match the spec.

**Proven to fire** (mutant or old code made the test fail): every row 1–9
above; validator: identity-point, EOCD-count, NaN, STORE-size checks.

**Stated but not yet proven by a dedicated case** (an evidence audit found
them): general-purpose bit 6 (corpus case also rejected by zipfile for an
unrelated reason), bit 13 (no case), ZIP64 (the corpus case is rejected by
the CD-ends-at-EOCD rule, not ZIP64 detection), S ≥ L and non-canonical R
(validator implements, no corpus case), decompressed length = declared size.

**Residual, known:** a newline INSIDE a package value quoted in an error
message on stderr is kept (the message's own line breaks cannot be told
apart there); everything else in it is escaped. `inspect --manifest` prints
raw manifest JSON with no authenticated marker (exit code 3 still says it).
The sticky-/tmp subcase reports a passing MESSAGE when run as root.

## Independent-implementation readiness

A spec-only reader (no source) found 27 gaps; the security-relevant ones that
both implementations already agreed on are now FORMAT text, the rest are in
A.7. What still requires the reference implementation to answer: the A.7
items above; the ELF/PE machine-to-architecture table and "valid ELF" header
requirements (§6.7 names fields, not a complete table); `build.toolchain` and
`build.command` limits (A.4 #19 only); and REFERENCE-POLICY cites "§14.4",
which is another document's numbering.

## Resources

Evidence run, metered (`scripts/resource-meter.sh`, `../lexe-resource-evidence/hardening-run-20261002.json`): peak tree RSS **1548 MiB** of 4096; rolling 10-second CPU **4.7%** peak of 50%. Builds at the existing `-j6`. Two of the subagents were run on Sonnet and one at a time against the WSL build; one lane run hit "Text file busy" during a rebuild and was re-run.

## First actions next time

1. ARM: unchanged — a conventional AArch64 Linux host with user namespaces,
   then `scripts/arm-worker.sh` + `scripts/second-isa.sh` (see `2c0a675`).
2. Decide the A.7 items, starting with file/directory prefix conflicts and
   unsigned in-record bytes (both: deterministic rejection, after checking
   what writers emit).
3. Add corpus cases for the "stated but not proven" list.
