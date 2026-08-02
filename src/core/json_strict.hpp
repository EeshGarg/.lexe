// json_strict — the ONE JSON entry point for every security-relevant document
// (HARDENING.md §E). Standard JSON permits duplicate object keys and libraries
// silently keep the first or the last; a package could then present
// `"publicKey": <attacker>, "publicKey": <real>` and have the verifier and a
// human reviewer disagree about which key signed it. parse() rejects duplicate
// keys anywhere in the document (recursively, at every nesting level) BEFORE
// building the DOM, so no caller can be fooled by parser key-precedence.
//
// It also enforces the byte budget for the document class (HARDENING.md §F):
// the raw text must not exceed the caller-supplied limit, checked before any
// allocation of the DOM.
//
// Use lexe::json_strict::parse / parse_ordered instead of nlohmann::*::parse
// for manifests, installation records, transaction journals, hashes.json,
// update manifests, key files and any policy/trust document.

#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string_view>

namespace lexe::json_strict {

/// Parse `text` as a JSON document, rejecting duplicate object keys and any
/// input larger than `max_bytes`. `context` names the document in error
/// messages (e.g. "manifest", "installation record"). Throws
/// lexe::VerificationError on duplicate keys, malformed JSON, invalid UTF-8, or
/// an over-budget document. Returns an (unordered) nlohmann::json.
nlohmann::json parse(std::string_view text, std::string_view context,
                     std::size_t max_bytes);

/// As parse(), but returns an ordered_json (preserves key order) for callers
/// that read-modify-write a document (e.g. the builder filling in publicKey).
nlohmann::ordered_json parse_ordered(std::string_view text,
                                     std::string_view context,
                                     std::size_t max_bytes);

} // namespace lexe::json_strict
