# Concurrency & Operation Locking (runtime-trust WS9)

This document describes how the `.lexe` runtime stays correct when multiple
processes touch the same installation at once — two installs racing, an update
landing while the app is running, a crash mid-mutation, a garbage collector
running beside a launch. The companion storage model (what data survives what)
is in [FORMAT-0.1.md §9](FORMAT-0.1.md).

The guiding principle is conservative: **a lock file existing is not proof of
mutual exclusion, and retained data surviving one happy-path update is not proof
of a coherent lifecycle.** Every guarantee below is backed by an OS mechanism and
an automated test, including real cross-process tests
(`tests/test_race_linux.cpp`) and a real-binary lifecycle run
(`tests/integration/ws8_ws9_lifecycle.sh`).

## Why not timestamps or check-then-create

A lock implemented as "does `foo.lock` exist? if not, create it" has two fatal
flaws: the check and the create are not atomic (two processes both see "no" and
both create), and a process that dies holding the lock leaves the file behind
forever, so implementations start *deleting* locks whose mtime looks old — which
races a slow-but-alive holder and corrupts state.

The runtime instead uses **OS-backed advisory locks** (`flock(2)` on Linux):

* Acquisition is atomic in the kernel — there is no check-then-create window.
* The lock is tied to the open file description, so the **kernel releases it the
  instant the holder dies** (exit, crash, `SIGKILL`). A leftover lock *file* on
  disk is therefore never, by itself, evidence that anyone holds the lock, and
  the runtime never deletes a lock file on a staleness heuristic.
* Owner metadata (pid + a per-process start token read from `/proc/self/stat`)
  is written into the lock file for **diagnostics only** and is never consulted
  to decide liveness. Because the start token changes when the kernel reuses a
  pid, a recycled pid can never be mistaken for the original holder.

On platforms without this mechanism (the Windows dev host) the abstraction falls
back to a permissive single-writer backend; isolation and multi-process
coordination are Linux features.

## The locks

All locks go through `OperationLockManager` (`src/core/lock.hpp`). The scopes are
distinct C++ types so a misuse is a compile error, not a runtime surprise.

| Lock | Type | Mode | Scope | Held for |
|---|---|---|---|---|
| Per-app mutation | `AppLock` | exclusive | one App ID | install / update / rollback / remove / repair / recover / cleanup |
| Launch lease | `LaunchLease` | shared | one (App ID, version) | the entire run of that version |
| Version GC hold | `LaunchLease` | exclusive (non-blocking) | one (App ID, version) | while GC/uninstall removes that version |
| Global recovery | `GlobalRecoveryLock` | exclusive | whole store | a `recover_all` pass |

* **Per-app mutation lock** (`locks/<id>.lock`). Two operations on the *same* App
  ID serialize on it; operations on *different* App IDs use different files and
  proceed concurrently. A contended acquisition waits up to a bounded interval,
  then fails with `BusyError` (exit 6) rather than blocking forever.
* **Launch lease** (`locks/<id>.v.<version>.lease`). A launch takes it *shared*,
  so any number of concurrent launches of the same version coexist; it is held
  by the launching process for the whole run. Because it is shared, it excludes
  only an *exclusive* holder — a GC or uninstall trying to remove that version.
* **Global recovery lock** (`locks/global.recovery.lock`). Serializes recovery
  passes with each other. It is taken only to enumerate work; per-app recovery
  then takes each app's own mutation lock, so unrelated App IDs are never
  serialized for the duration of their recovery.

## Lock ordering (deadlock avoidance)

Locks are always acquired in increasing class order, and a holder of a later
class never blocks to take an earlier one:

```
GlobalRecovery  >  AppMutation  >  VersionLease  >  Registry
```

`recover_all` (GlobalRecovery) takes each app's `AppLock` under it; a launch
takes a `VersionLease` after (briefly, during resolution) any AppMutation
concern is past. The order is asserted at runtime by a per-thread tripwire in
`lock.cpp` (`order_register`/`order_unregister`) — a regression that acquires out
of order trips an assertion in debug builds.

## Guaranteed behaviors

* **Two same-App installs** → exactly one mutates; the other waits briefly then
  reports busy. **Two different-App installs** → fully concurrent.
* **Install/update while launching** → the launch resolves and runs the version
  that was active when it started; activation (the `current` flip) is atomic, so
  a launch never sees a torn mix. See TOCTOU below.
* **Upgrade while the old version is running** → the old process keeps running
  and its version is **not** garbage-collected: the running launcher holds a
  shared lease that blocks the version's exclusive GC hold.
* **Uninstall while launching** → refused with `BusyError` ("currently running"),
  never a silent deletion of files out from under a live process. The uninstaller
  holds the exclusive version holds across the removal so a launch cannot start
  mid-uninstall.
* **Recovery serializes with same-App mutation** (shared `AppLock`) and recovery
  passes serialize with each other (global lock).
* **Process death releases every lock immediately** — proven by SIGKILLing a
  holder in `test_race_linux.cpp` and having another process acquire at once.

## TOCTOU closure around launch

The launch path is resolve → validate → hash → isolate → exec. The window to
close is between resolving which version is active and actually executing it: a
concurrent update could flip `current`, and a GC could remove the resolved
version.

The launcher (`src/core/launcher.cpp`):

1. resolves the active version once,
2. immediately takes a **shared launch lease** on that exact `(id, version)` and
   holds it for the whole run,
3. from then on uses only the **immutable** `versions/<version>` path — `current`
   is never re-read — so a later flip cannot retarget the launch,
4. revalidates that the version directory still exists *after* leasing (fail
   closed if it lost a race), then hash-checks the entrypoint against the
   recorded digest before exec.

The active version is, by definition, retained by the conservative GC, so it
cannot vanish in the microscopic resolve→lease window; once the lease is held it
cannot vanish for the rest of the run. The lease's file descriptor is
`O_CLOEXEC`, so the sandboxed child never inherits or observes it.

## Typed errors

Concurrency and lifecycle failures are distinct exception types, so tests and
callers never match on free-form text:

| Condition | Type | Exit |
|---|---|---|
| App busy / mutation or recovery in progress / purge refused, active lease | `BusyError` | 6 |
| Retained data belongs to a different publisher key | `RetainedDataConflict` | 6 |
| Lock file unopenable / lock metadata corrupt / OS lock failure | `LockError` | 1 |
| Launch precondition (version gone, integrity) | `LaunchError` | 1 |
