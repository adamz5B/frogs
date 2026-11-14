//! Best-effort scrubbing of free text before it leaves the authoring server. The primary control is
//! that tools only ever return allowlisted fields; this catches the two shapes a driver or parser
//! error most often drags a credential in with: URL userinfo and `password=`/`pwd=` values.

use serde_json::Value;

const MASK: &str = "***";
const PARAM_KEYS: [&str; 2] = ["password", "pwd"];

fn ends_value(c: char) -> bool {
    c.is_whitespace() || matches!(c, ';' | '&' | '"' | '\'' | ',' | ')' | '>')
}

pub(crate) fn redact(text: &str) -> String {
    redact_params(&redact_userinfo(text))
}

/// `scheme://user:secret@host` -> `scheme://user:***@host`. Only the password part changes; a bare `user@host` stays.
fn redact_userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let authority_end = tail
            .find(|c: char| matches!(c, '/' | '?' | '#') || c.is_whitespace() || matches!(c, '"' | '\''))
            .unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        match authority.rfind('@') {
            Some(at_sign) => {
                let userinfo = &authority[..at_sign];
                match userinfo.find(':') {
                    Some(colon) => {
                        out.push_str(&userinfo[..colon]);
                        out.push(':');
                        out.push_str(MASK);
                    }
                    None => out.push_str(userinfo),
                }
                out.push_str(&authority[at_sign..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[authority_end..];
    }
    out.push_str(rest);
    out
}

/// `password=hunter2;` -> `password=***;`, matched case-insensitively on a word boundary.
fn redact_params(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut search = 0;
    while search < lower.len() {
        let hit = PARAM_KEYS
            .iter()
            .filter_map(|key| lower[search..].find(key).map(|pos| (search + pos, key.len())))
            .min_by_key(|(pos, _)| *pos);
        let Some((start, key_len)) = hit else { break };
        let before_ok = text[..start].chars().next_back().is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        let after = start + key_len;
        let mut value_start = after;
        let spaced = text[after..].chars().take_while(|c| *c == ' ').count();
        value_start += spaced;
        if before_ok && text[value_start..].starts_with('=') {
            value_start += 1;
            value_start += text[value_start..].chars().take_while(|c| *c == ' ').count();
            let value_len = text[value_start..].find(ends_value).unwrap_or(text.len() - value_start);
            out.push_str(&text[cursor..value_start]);
            out.push_str(MASK);
            cursor = value_start + value_len;
            search = cursor;
        } else {
            search = after;
        }
    }
    out.push_str(&text[cursor..]);
    out
}

/// Every string in a result tree, in place.
pub(crate) fn redact_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = redact(text),
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        Value::Object(map) => map.values_mut().for_each(redact_value),
        _ => {}
    }
}
