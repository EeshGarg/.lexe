// json_strict — see json_strict.hpp. Duplicate-key rejection is done with a
// nlohmann SAX handler (the DOM parser and the parser_callback both keep a
// last-key-wins policy and cannot reject duplicates); a first pass runs the
// detector, and only a clean document is materialized into the DOM.

#include "lexe/base/json_strict.hpp"

#include "lexe/base/error.hpp"

#include <set>
#include <string>
#include <vector>

namespace lexe::json_strict {

namespace {

/// nlohmann SAX consumer that accepts nothing but records structure enough to
/// reject a duplicate key at any object nesting level. It builds no DOM — it
/// only validates. `key()` returns false (aborting the parse) the moment a key
/// repeats within the current object.
struct DuplicateKeyDetector {
    using number_integer_t = nlohmann::json::number_integer_t;
    using number_unsigned_t = nlohmann::json::number_unsigned_t;
    using number_float_t = nlohmann::json::number_float_t;
    using string_t = nlohmann::json::string_t;
    using binary_t = nlohmann::json::binary_t;

    std::vector<std::set<std::string>> object_keys; // one set per open object
    std::string error;

    bool null() { return true; }
    bool boolean(bool) { return true; }
    bool number_integer(number_integer_t) { return true; }
    bool number_unsigned(number_unsigned_t) { return true; }
    bool number_float(number_float_t, const string_t&) { return true; }
    bool string(string_t&) { return true; }
    bool binary(binary_t&) { return true; }

    bool start_object(std::size_t) {
        object_keys.emplace_back();
        return true;
    }
    bool key(string_t& val) {
        if (!object_keys.back().insert(val).second) {
            error = "duplicate object key \"" + val + "\"";
            return false; // abort the parse
        }
        return true;
    }
    bool end_object() {
        object_keys.pop_back();
        return true;
    }
    bool start_array(std::size_t) { return true; }
    bool end_array() { return true; }

    bool parse_error(std::size_t /*position*/, const std::string& /*token*/,
                     const nlohmann::json::exception& ex) {
        if (error.empty()) error = ex.what();
        return false;
    }
};

void check_budget(std::string_view text, std::string_view context,
                  std::size_t max_bytes) {
    if (text.size() > max_bytes) {
        throw VerificationError(std::string(context) + ": document is " +
                                std::to_string(text.size()) +
                                " bytes, exceeds the " +
                                std::to_string(max_bytes) + "-byte limit");
    }
}

/// Reject a UTF-8 byte-order mark before the top-level value.
///
/// FORMAT-0.1 §5.0 applies to EVERY JSON document the format defines --
/// `lexe.json`, `metadata/hashes.json` and `update.json` -- and this check used
/// to live in `Manifest::parse` instead, which meant it applied to exactly one
/// of the three. A package whose stored `hashes.json` began `ef bb bf` reported
/// `verification: OK (signature valid, Ed25519)`, while the same three bytes on
/// `lexe.json` were correctly refused.
///
/// The lesson is about WHERE a rule lives rather than about the rule. A
/// requirement written once per document is a requirement that will hold for the
/// documents somebody remembered; a requirement enforced in the one function
/// every document goes through holds for all of them, including the next one
/// this format defines. Every other §5.0 obligation -- duplicate keys, UTF-8
/// validity, trailing data, the byte budget -- was already here, and the BOM was
/// the odd one out.
void reject_bom(std::string_view text, std::string_view context) {
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF) {
        throw VerificationError(std::string(context) +
                                ": UTF-8 BOM is not allowed");
    }
}

/// A raw NUL byte is never valid JSON (RFC 8259: not whitespace, and a string
/// must escape it). It must be rejected BEFORE nlohmann sees the text: its
/// lexer treats 0x00 as end-of-input, so "{...}\0anything" parsed as "{...}"
/// and signed bytes after the NUL were silently ignored (§5.0 trailing data).
void reject_nul(std::string_view text, std::string_view context) {
    if (text.find('\0') != std::string_view::npos) {
        throw VerificationError(std::string(context) +
                                ": contains a NUL byte (not valid JSON; "
                                "nothing after it may be ignored)");
    }
}

void reject_duplicates(std::string_view text, std::string_view context) {
    DuplicateKeyDetector detector;
    // strict=true validates trailing data and UTF-8; the DETECTOR aborts on the
    // first duplicate key. A false return means either a duplicate key or a
    // syntax/UTF-8 error — both are reported the same way (the DOM parse below
    // will not be reached).
    const bool ok = nlohmann::json::sax_parse(text, &detector);
    if (!ok) {
        throw VerificationError(std::string(context) + ": " +
                                (detector.error.empty()
                                     ? "invalid JSON"
                                     : detector.error));
    }
}

} // namespace

nlohmann::json parse(std::string_view text, std::string_view context,
                     std::size_t max_bytes) {
    check_budget(text, context, max_bytes);
    reject_bom(text, context);
    reject_nul(text, context);
    reject_duplicates(text, context);
    // The SAX pass already proved the text is well-formed, duplicate-free UTF-8
    // JSON; this DOM parse cannot fail, but stay defensive.
    nlohmann::json doc = nlohmann::json::parse(text, nullptr,
                                               /*allow_exceptions=*/false);
    if (doc.is_discarded()) {
        throw VerificationError(std::string(context) + ": invalid JSON");
    }
    return doc;
}

nlohmann::ordered_json parse_ordered(std::string_view text,
                                     std::string_view context,
                                     std::size_t max_bytes) {
    check_budget(text, context, max_bytes);
    reject_bom(text, context);
    reject_nul(text, context);
    reject_duplicates(text, context);
    nlohmann::ordered_json doc = nlohmann::ordered_json::parse(
        text, nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded()) {
        throw VerificationError(std::string(context) + ": invalid JSON");
    }
    return doc;
}

} // namespace lexe::json_strict
