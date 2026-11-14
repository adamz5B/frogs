//! Era selection and line serialisation on the stdio transport (`Transport::Stdio`): no `MCP-*` headers exist
//! there, so the era comes from the body alone. `protocol_tests.rs` covers the HTTP transport and is untouched.

use serde_json::Value;

use super::protocol::*;

fn stdio(body: &str) -> Result<Era, ProtoError> {
    let Parsed::Request(request) = parse_envelope(body.as_bytes()).unwrap_or_else(|e| panic!("envelope refused ({}): {body}", e.code)) else {
        panic!("expected a request, got a notification: {body}");
    };
    let params = parse_params(request.params.as_deref())?;
    negotiate_for(Transport::Stdio, &request, &params)
}

fn modern(method: &str, extra_meta: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28"{extra_meta}}}}}}}"#)
}

const CAPS: &str = r#","io.modelcontextprotocol/clientCapabilities":{}"#;

#[test]
fn a_request_with_no_meta_at_all_is_the_legacy_era_on_stdio() {
    assert_eq!(stdio(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap(), Era::Legacy);
}

#[test]
fn initialize_is_always_legacy_on_stdio_even_when_it_carries_a_modern_meta_version() {
    assert_eq!(stdio(&modern("initialize", CAPS)).unwrap(), Era::Legacy);
}

#[test]
fn a_modern_meta_version_with_a_capabilities_object_is_the_modern_era_with_no_headers_at_all() {
    assert_eq!(stdio(&modern("tools/list", CAPS)).unwrap(), Era::Modern);
}

#[test]
fn a_modern_meta_version_without_client_capabilities_is_invalid_params() {
    assert_eq!(stdio(&modern("tools/list", "")).err().unwrap().code, INVALID_PARAMS);
}

#[test]
fn modern_client_capabilities_that_are_not_an_object_are_invalid_params() {
    for bad in [
        r#","io.modelcontextprotocol/clientCapabilities":[]"#,
        r#","io.modelcontextprotocol/clientCapabilities":"x""#,
        r#","io.modelcontextprotocol/clientCapabilities":null"#,
    ] {
        assert_eq!(stdio(&modern("tools/list", bad)).err().unwrap().code, INVALID_PARAMS, "{bad}");
    }
}

#[test]
fn an_unsupported_meta_version_is_32022_with_supported_and_requested_data() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}}"#;
    let error = stdio(body).err().unwrap();
    assert_eq!(error.code, UNSUPPORTED_VERSION);
    let data = error.data.expect("an unsupported-version error carries data");
    assert_eq!(data["requested"], "1999-01-01");
    assert!(data["supported"].as_array().unwrap().iter().any(|v| v == "2026-07-28"), "{data}");
}

#[test]
fn a_legacy_meta_version_stays_legacy_on_stdio_without_capabilities() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}"#;
    assert_eq!(stdio(body).unwrap(), Era::Legacy);
}

#[test]
fn a_non_string_meta_version_is_invalid_params() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":7}}}"#;
    assert_eq!(stdio(body).err().unwrap().code, INVALID_PARAMS);
}

#[test]
fn stdio_never_produces_the_header_mismatch_error_for_any_modern_method() {
    for method in ["tools/list", "tools/call", "server/discover"] {
        let result = stdio(&modern(method, CAPS));
        assert!(result.is_ok(), "{method}: {:?}", result.err().map(|e| e.code));
    }
}

#[test]
fn an_error_line_is_one_compact_json_line_with_the_id_echoed_verbatim() {
    let Parsed::Request(request) = parse_envelope(br#"{"jsonrpc":"2.0","id":"abc","method":"x"}"#).unwrap() else {
        panic!()
    };
    let line = ProtoError::method_not_found().into_line(Some(&request.id));
    assert!(!line.contains('\n'));
    let value: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["id"], "abc");
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["error"]["code"], METHOD_NOT_FOUND);
}

#[test]
fn an_error_line_without_an_id_has_a_null_id() {
    let value: Value = serde_json::from_str(&ProtoError::new(PARSE_ERROR, "Parse error").into_line(None)).unwrap();
    assert_eq!(value["id"], Value::Null);
    assert_eq!(value["error"]["code"], PARSE_ERROR);
}

#[test]
fn a_result_line_wraps_the_raw_result_and_keeps_numeric_ids_as_numbers() {
    let Parsed::Request(request) = parse_envelope(br#"{"jsonrpc":"2.0","id":42,"method":"x"}"#).unwrap() else {
        panic!()
    };
    let result = serde_json::value::to_raw_value(&serde_json::json!({ "a": 1 })).unwrap();
    let line = result_line(&request.id, &result).expect("a plain result serialises");
    assert!(!line.contains('\n'));
    let value: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["id"], 42);
    assert_eq!(value["result"]["a"], 1);
}
