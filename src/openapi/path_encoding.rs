//! Canonical spelling of a request path (RFC 3986 section 6.2.2.2: `%41` and
//! `A` name the same segment), so one resource has one spelling before any
//! router sees it. Pure byte logic; no routing types.

use std::borrow::Cow;
use std::collections::BTreeSet;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode, percent_encode};

/// Every byte that is not an RFC 3986 `pchar`: all but unreserved (`- . _ ~`
/// plus alphanumerics), sub-delims and `:` `@`. Includes `%` and `/`.
const PCHAR_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=')
    .remove(b':')
    .remove(b'@');

fn is_pchar_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@'
        )
}

/// Whether every character is an unencoded `pchar` (`%` and `/` are not).
pub fn is_pchar_str(s: &str) -> bool {
    s.bytes().all(is_pchar_byte)
}

/// Percent-encodes one literal (already decoded) segment; never decodes.
/// Non-ASCII text is put in NFC first, so a folder stored decomposed (macOS)
/// is registered under the one spelling `canonicalize_path_with` rewrites
/// matching request segments to.
pub fn encode_literal_segment(seg: &str) -> Cow<'_, str> {
    if is_pchar_str(seg) {
        Cow::Borrowed(seg)
    } else {
        use unicode_normalization::UnicodeNormalization;
        let composed: String = seg.nfc().collect();
        Cow::Owned(percent_encode(composed.as_bytes(), PCHAR_ENCODE).to_string())
    }
}

/// The NFC spelling of `seg` when it contains non-ASCII text, else `None`:
/// the key under which a registered literal is remembered for
/// `canonicalize_path_with`.
pub fn nfc_literal_key(seg: &str) -> Option<String> {
    use unicode_normalization::UnicodeNormalization;
    (!seg.is_ascii()).then(|| seg.nfc().collect())
}

/// One wire segment in canonical form: leniently decoded (a `%` not followed
/// by two hex digits stays literal, as in axum), then re-encoded so only
/// `pchar` bytes stay bare. A decoded `.` or `..` stays encoded: this never
/// creates a dot segment that was not literally on the wire.
#[cfg(test)]
pub fn canonicalize_segment(raw: &[u8]) -> Cow<'_, str> {
    canonicalize_segment_with(raw, &BTreeSet::new())
}

/// `canonicalize_segment`, plus: a decoded non-ASCII segment that is not in NFC
/// is rewritten to its NFC spelling when (and only when) that spelling is one
/// of `literals`. Axum matches literal segments byte for byte, so without this
/// a decomposed spelling of a literal folder would fall through to a sibling
/// `{param}` route; limiting it to registered literals leaves every parameter
/// value exactly as the client sent it.
pub fn canonicalize_segment_with<'a>(raw: &'a [u8], literals: &BTreeSet<String>) -> Cow<'a, str> {
    let mut decoded = percent_decode(raw).collect::<Vec<u8>>();
    if !literals.is_empty()
        && !decoded.is_ascii()
        && let Ok(text) = std::str::from_utf8(&decoded)
        && let Some(composed) = nfc_literal_key(text)
        && composed != text
        && literals.contains(&composed)
    {
        decoded = composed.into_bytes();
    }
    let canonical = match decoded.as_slice() {
        b"." => "%2E".to_string(),
        b".." => "%2E%2E".to_string(),
        other => percent_encode(other, PCHAR_ENCODE).to_string(),
    };
    match std::str::from_utf8(raw) {
        Ok(text) if text == canonical => Cow::Borrowed(text),
        _ => Cow::Owned(canonical),
    }
}

fn already_canonical(raw: &str) -> bool {
    raw.split('/').all(|seg| seg != "." && seg != ".." && is_pchar_str(seg))
}

/// The canonical form of a whole request path, slashes (including empty
/// segments) preserved exactly. A path that does not start with `/` (`*`
/// from `OPTIONS *`) is returned as is. Borrowed when nothing changes.
#[cfg(test)]
pub fn canonicalize_path(raw: &str) -> Cow<'_, str> {
    canonicalize_path_with(raw, &BTreeSet::new())
}

/// `canonicalize_path` with the registered-literal NFC rewrite of `canonicalize_segment_with`.
pub fn canonicalize_path_with<'a>(raw: &'a str, literals: &BTreeSet<String>) -> Cow<'a, str> {
    if !raw.starts_with('/') || already_canonical(&raw[1..]) {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    for seg in raw[1..].split('/') {
        out.push('/');
        out.push_str(&canonicalize_segment_with(seg.as_bytes(), literals));
    }
    if out == raw { Cow::Borrowed(raw) } else { Cow::Owned(out) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lenient_decode(raw: &str) -> Vec<u8> {
        percent_decode(raw.as_bytes()).collect()
    }

    fn lcg(state: &mut u64) -> u64 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *state >> 33
    }

    const PCHARS: &str = "abcXYZ019-._~!$&'()*+,;=:@";

    #[test]
    fn the_canonical_form_table_matches_the_documented_spellings() {
        let table = [
            ("/caf%c3%a9/menu", "/caf%C3%A9/menu"),
            ("/café/menu", "/caf%C3%A9/menu"),
            ("/%41/x", "/A/x"),
            ("/%2541/x", "/%2541/x"),
            ("/a%2Fb", "/a%2Fb"),
            ("/a%2fb", "/a%2Fb"),
            ("/%2e%2E/x", "/%2E%2E/x"),
            ("/../x", "/%2E%2E/x"),
            ("/./x", "/%2E/x"),
            ("/%2e/x", "/%2E/x"),
            ("/%zz", "/%25zz"),
            ("/%", "/%25"),
            ("/a%2", "/a%252"),
            ("/q\"t", "/q%22t"),
            ("/%7e", "/~"),
            ("/%3A", "/:"),
            ("/x/", "/x/"),
            ("//", "//"),
            ("/", "/"),
            ("*", "*"),
            ("/a b", "/a%20b"),
            ("/a%20b", "/a%20b"),
        ];
        for (input, expected) in table {
            assert_eq!(canonicalize_path(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn every_pchar_character_is_left_bare_and_every_other_ascii_byte_is_encoded_uppercase() {
        for b in 0u8..=127 {
            let seg = (b as char).to_string();
            let encoded = encode_literal_segment(&seg).into_owned();
            if is_pchar_byte(b) {
                assert_eq!(encoded, seg, "byte {b}");
            } else {
                assert_eq!(encoded, format!("%{b:02X}"), "byte {b}");
            }
        }
        assert_eq!(encode_literal_segment(PCHARS), PCHARS);
        assert!(matches!(encode_literal_segment(PCHARS), Cow::Borrowed(_)));
    }

    #[test]
    fn an_already_canonical_path_is_returned_borrowed_without_allocating() {
        for p in ["/", "/a/b", "/caf%C3%A9/menu", "/a%2Fb", "/x/", "//", "*", "/%2E/x"] {
            assert!(matches!(canonicalize_path(p), Cow::Borrowed(_)), "{p}");
        }
        assert!(matches!(canonicalize_path("/%41"), Cow::Owned(_)));
    }

    fn check_invariants(path: &str) {
        let canon = canonicalize_path(path).into_owned();
        assert_eq!(canonicalize_path(&canon), canon, "idempotence for {path:?}");
        assert_eq!(canon.matches('/').count(), path.matches('/').count(), "slash count for {path:?}");
        if path.starts_with('/') {
            for seg in canon[1..].split('/') {
                assert!(seg != "." && seg != "..", "dot segment created from {path:?}: {canon:?}");
                let bytes = seg.as_bytes();
                let mut i = 0;
                while i < bytes.len() {
                    if bytes[i] == b'%' {
                        let hex = &bytes[i + 1..(i + 3).min(bytes.len())];
                        assert!(
                            hex.len() == 2 && hex.iter().all(|h| h.is_ascii_digit() || (b'A'..=b'F').contains(h)),
                            "bad escape in {canon:?} from {path:?}"
                        );
                        i += 3;
                    } else {
                        assert!(is_pchar_byte(bytes[i]), "non-pchar byte in {canon:?} from {path:?}");
                        i += 1;
                    }
                }
            }
            assert_eq!(lenient_decode(&canon), lenient_decode(path), "decode equivalence for {path:?}");
        }
    }

    #[test]
    fn exhaustive_short_paths_over_a_small_alphabet_keep_the_canonical_invariants() {
        let alphabet: [&str; 12] = ["a", "/", "%", "2", "F", "E", "e", ".", "A", "3", "C", " "];
        let mut count = 0usize;
        let mut stack: Vec<Vec<usize>> = vec![vec![]];
        while let Some(current) = stack.pop() {
            let text: String = current.iter().map(|&i| alphabet[i]).collect();
            check_invariants(&format!("/{text}"));
            count += 1;
            if current.len() < 5 {
                for i in 0..alphabet.len() {
                    let mut next = current.clone();
                    next.push(i);
                    stack.push(next);
                }
            }
        }
        assert!(count > 250_000, "{count}");
    }

    #[test]
    fn random_byte_strings_keep_the_canonical_segment_invariants() {
        let pool: [u8; 14] = *b"a/%2FEe.A3C \xC3\xA9";
        let mut state = 7u64;
        for _ in 0..100_000 {
            let len = (lcg(&mut state) % 41) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    let r = lcg(&mut state);
                    if r.is_multiple_of(5) {
                        (r >> 3) as u8
                    } else {
                        pool[(r >> 3) as usize % pool.len()]
                    }
                })
                .collect();
            let seg: Vec<u8> = bytes.iter().copied().filter(|b| *b != b'/').collect();
            let canon = canonicalize_segment(&seg).into_owned();
            assert_eq!(canonicalize_segment(canon.as_bytes()), canon, "idempotence for {seg:?}");
            assert_eq!(
                percent_decode(canon.as_bytes()).collect::<Vec<u8>>(),
                percent_decode(&seg).collect::<Vec<u8>>(),
                "decode equivalence for {seg:?}"
            );
            assert!(canon.bytes().all(|b| b == b'%' || is_pchar_byte(b)), "{canon:?}");
            if let Ok(text) = String::from_utf8(bytes) {
                check_invariants(&format!("/{text}"));
            }
        }
    }

    #[test]
    fn every_spelling_of_a_literal_segment_canonicalizes_to_its_encoded_literal() {
        for lit in ["café", "a b", "q\"t", "A", "x{y}", "日本", "a;b=c", "~tilde", "a+b"] {
            let expected = encode_literal_segment(lit).into_owned();
            let bytes = lit.as_bytes();
            for mask in 0u32..(1 << bytes.len().min(10)) {
                for lower in [false, true] {
                    let mut spelled = String::new();
                    for (i, b) in bytes.iter().enumerate() {
                        if (i < 10 && mask & (1 << i) != 0) || !b.is_ascii() {
                            spelled.push_str(&if lower { format!("%{b:02x}") } else { format!("%{b:02X}") });
                        } else {
                            spelled.push(*b as char);
                        }
                    }
                    assert_eq!(canonicalize_path(&format!("/{spelled}")), format!("/{expected}"), "{lit:?} spelled {spelled:?}");
                }
            }
            assert_eq!(canonicalize_path(&format!("/{lit}")), format!("/{expected}"), "raw {lit:?}");
        }
    }

    #[test]
    fn a_percent_encoded_slash_never_becomes_a_separator_and_a_decoded_dot_never_becomes_a_dot_segment() {
        assert_eq!(canonicalize_path("/a%2Fb/c"), "/a%2Fb/c");
        assert_eq!(canonicalize_path("/..%2Fsecret"), "/..%2Fsecret");
        assert_eq!(canonicalize_path("/%2E%2E%2Fsecret"), "/..%2Fsecret");
        assert_eq!(canonicalize_path("/..%5Csecret"), "/..%5Csecret");
        assert_eq!(canonicalize_path("/a/%2e%2e/%2e%2e/secret"), "/a/%2E%2E/%2E%2E/secret");
    }

    #[test]
    fn a_decomposed_spelling_becomes_nfc_only_when_that_is_a_registered_literal() {
        let literals: BTreeSet<String> = ["caf\u{e9}".to_string()].into();
        let decomposed = "/cafe\u{301}/menu";
        assert_eq!(canonicalize_path_with(decomposed, &literals), "/caf%C3%A9/menu");
        assert_eq!(canonicalize_path_with("/cafe%CC%81/menu", &literals), "/caf%C3%A9/menu");
        // No registered literal: the value is left exactly as sent, so a parameter keeps its spelling.
        assert_eq!(canonicalize_path_with(decomposed, &BTreeSet::new()), "/cafe%CC%81/menu");
        assert_eq!(canonicalize_path_with("/nai\u{308}ve", &literals), "/nai%CC%88ve");
    }

    #[test]
    fn encode_literal_segment_puts_non_ascii_in_nfc() {
        assert_eq!(encode_literal_segment("cafe\u{301}"), encode_literal_segment("caf\u{e9}"));
        assert_eq!(nfc_literal_key("cafe\u{301}").as_deref(), Some("caf\u{e9}"));
        assert_eq!(nfc_literal_key("cafe"), None);
    }

    #[test]
    fn is_pchar_str_rejects_percent_slash_space_and_non_ascii() {
        assert!(is_pchar_str(PCHARS));
        for bad in ["a%", "a/b", "a b", "é", "a\"", "{x}", "a?b", "a#b", "a[b"] {
            assert!(!is_pchar_str(bad), "{bad}");
        }
    }
}
