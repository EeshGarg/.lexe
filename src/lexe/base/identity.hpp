#pragma once
// identity — what an Application ID and a version string are allowed to be.
//
// These two rules are stated HERE, once, because they are the only strings in
// .LEXE that are simultaneously manifest data, path components, and file
// contents. Every layer that touches either one needs the same answer:
//
//   * `package/manifest` refuses a bad one at parse time, so an unusable
//     package cannot be built;
//   * `state/registry` refuses one again, because installed state can arrive
//     from somewhere other than a package this runtime built;
//   * `state/appconfig`, `diagnostics`, `integration` and `runtime/launchref`
//     all join an id into a path and must agree on what is safe to join.
//
// They live in `base/` rather than beside the registry because `package/` is
// below `state/` in the layering (docs/ARCHITECTURE.md) and must not reach up to
// it. When the rule lived in the registry, the manifest carried its own second
// copy — and the two copies did not agree, which is exactly the failure mode
// this file exists to remove.
//
// The version rule is the one with a scar. FORMAT-0.1 §5 calls the version
// free-form and §8 only defines an ORDER over it, so both copies allowed
// whitespace. But a version is also the entire contents of
// `apps/<id>/current.txt` on a host where the `current` symlink cannot be
// created, and that file is read back through trim_whitespace. A version of
// `"1.0.0 "` was therefore written faithfully and read back as `"1.0.0"`: the
// runtime resolved a current version whose directory did not exist, and the
// application could not launch. Two components disagreed about what a version
// may contain, and the one that could not represent it lost silently.

#include <string>

namespace lexe {

/// True when `id` has the FORMAT-0.1 §5 reverse-DNS shape: two or more
/// dot-separated segments of [a-zA-Z0-9-]+, at most 255 characters.
///
/// Because that shape excludes path separators, drive designators and `.`/`..`
/// segments, a valid id is always safe to use as a single path component.
bool app_id_is_valid(const std::string& id);

/// app_id_is_valid, throwing lexe::Error with `context` in the message.
void validate_app_id(const std::string& id, const char* context);

/// True when `version` is usable everywhere .LEXE puts a version: as a path
/// component under `versions/`, inside lock and lease file names, and as the
/// whole contents of `current.txt`.
///
/// Non-empty, at most 64 characters, no whitespace, no control characters, no
/// path separator or drive designator, and not `.` or `..`. See the file comment
/// for why whitespace in particular is excluded.
bool version_string_is_valid(const std::string& version);

/// version_string_is_valid, throwing lexe::Error with `context` in the message.
void validate_version_string(const std::string& version, const char* context);

} // namespace lexe
