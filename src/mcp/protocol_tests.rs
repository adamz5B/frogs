//! JSON-RPC envelope, duplicate-key and era-negotiation behaviour of `mcp::protocol`.

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine;
use serde_json::Value;

use super::protocol::*;

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
    }
    map
}

fn envelope_error(body: &str) -> ProtoError {
    match parse_envelope(body.as_bytes()) {
        Err(error) => error,
        Ok(_) => panic!("expected the envelope to be refused: {body}"),
    }
}

fn negotiate_with(pairs: &[(&str, &str)], body: &str) -> Result<Era, ProtoError> {
    let Parsed::Request(request) = parse_envelope(body.as_bytes()).unwrap_or_else(|e| panic!("envelope refused ({}): {body}", e.code)) else {
        panic!("expected a request, got a notification: {body}");
    };
    let params = parse_params(request.params.as_deref())?;
    negotiate(&headers(pairs), &request, &params)
}

const MODERN_META: &str = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#;

fn modern_call(name: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}",{MODERN_META}}}}}"#)
}

fn modern_headers(name: &str) -> Vec<(&'static str, &str)> {
    vec![("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/call"), ("mcp-name", name)]
}

async fn body_json(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---- duplicate keys

#[test]
fn a_duplicate_top_level_method_is_invalid_request() {
    let error = envelope_error(r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}"#);
    assert_eq!(error.code, INVALID_REQUEST);
}

#[test]
fn a_duplicate_params_name_is_invalid_params_before_any_header_comparison() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}"#;
    assert_eq!(envelope_error(body).code, INVALID_PARAMS);
}

#[test]
fn a_duplicate_meta_protocol_version_is_invalid_params() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}"#;
    assert_eq!(envelope_error(body).code, INVALID_PARAMS);
}

#[test]
fn duplicate_argument_keys_and_duplicates_nested_inside_a_body_value_are_invalid_params() {
    let top = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"vin":"1","vin":"2"}}}"#;
    assert_eq!(envelope_error(top).code, INVALID_PARAMS);
    let nested = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"body":{"deep":[{"k":1,"k":2}]}}}}"#;
    assert_eq!(envelope_error(nested).code, INVALID_PARAMS, "stricter than HTTP, which keeps the last value");
}

#[test]
fn two_keys_that_decode_to_the_same_string_count_as_duplicates() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}"#;
    assert_eq!(envelope_error(body).code, INVALID_PARAMS);
    let top = r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"x"}"#;
    assert_eq!(envelope_error(top).code, INVALID_REQUEST);
}

#[test]
fn the_same_key_in_two_sibling_objects_is_not_a_duplicate() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"a":{"x":1},"b":{"x":2}}}}"#;
    assert!(parse_envelope(body.as_bytes()).is_ok());
}

// ---- envelope

#[test]
fn invalid_json_is_a_parse_error_whose_message_never_echoes_the_request() {
    let error = envelope_error(r#"{"jsonrpc":"2.0","secret-token-xyz"#);
    assert_eq!(error.code, PARSE_ERROR);
    assert_eq!(error.message, "Parse error");
    assert!(error.data.is_none());
}

#[tokio::test]
async fn the_parse_error_response_body_contains_no_request_content() {
    let error = envelope_error(r#"{"jsonrpc":"2.0","id":"super-secret-id","method":"x" "oops"#);
    let response = error.into_response(Era::Legacy, None);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!text.contains("secret"), "{text}");
    assert!(text.contains("Parse error"), "{text}");
}

#[test]
fn a_batch_a_scalar_a_wrong_version_a_non_string_method_and_a_null_id_are_all_invalid_request() {
    for body in [
        r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
        "  [ ]",
        "5",
        r#""text""#,
        r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
        r#"{"id":1,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":5}"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
        r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
    ] {
        assert_eq!(envelope_error(body).code, INVALID_REQUEST, "{body}");
    }
}

#[test]
fn a_nesting_deeper_than_the_json_limit_is_a_parse_error_with_a_fixed_message() {
    let deep = format!("{}{}", "[".repeat(300), "]".repeat(300));
    let error = envelope_error(&deep);
    assert_eq!(error.code, PARSE_ERROR);
    assert_eq!(error.message, "Parse error");
}

#[test]
fn a_request_without_an_id_is_a_notification_whatever_its_method() {
    for method in ["tools/call", "ping", "notifications/initialized", "nonsense"] {
        let body = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{{"name":"x"}}}}"#);
        assert!(matches!(parse_envelope(body.as_bytes()), Ok(Parsed::Notification)), "{method}");
    }
}

#[test]
fn string_and_number_ids_are_kept_verbatim_including_a_big_number() {
    for id in [r#""abc""#, "7", "12345678901234567890"] {
        let body = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
        let Ok(Parsed::Request(request)) = parse_envelope(body.as_bytes()) else {
            panic!("{id}")
        };
        assert_eq!(request.id.get(), id);
    }
}

// ---- era matrix

#[test]
fn initialize_is_always_legacy_even_with_a_modern_header() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#;
    assert_eq!(negotiate_with(&[], body).unwrap(), Era::Legacy);
    assert_eq!(negotiate_with(&[("mcp-protocol-version", "2026-07-28")], body).unwrap(), Era::Legacy);
}

#[test]
fn a_request_with_no_version_signal_is_served_with_legacy_semantics() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    assert_eq!(negotiate_with(&[], body).unwrap(), Era::Legacy);
    assert_eq!(negotiate_with(&[("mcp-protocol-version", "2025-06-18")], body).unwrap(), Era::Legacy);
}

#[test]
fn an_unsupported_header_version_is_32022_with_the_supported_list_in_both_eras() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let error = negotiate_with(&[("mcp-protocol-version", "1999-01-01")], body).unwrap_err();
    assert_eq!(error.code, UNSUPPORTED_VERSION);
    let data = error.data.unwrap();
    assert_eq!(data["requested"], "1999-01-01");
    assert_eq!(data["supported"], serde_json::json!(["2026-07-28", "2025-11-25", "2025-06-18"]));
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
    assert_eq!(negotiate_with(&[("mcp-protocol-version", "1999-01-01")], init).unwrap_err().code, UNSUPPORTED_VERSION);
}

#[test]
fn the_requested_version_in_a_32022_error_is_truncated_to_64_bytes() {
    let long = "v".repeat(300);
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let error = negotiate_with(&[("mcp-protocol-version", &long)], body).unwrap_err();
    assert_eq!(error.data.unwrap()["requested"].as_str().unwrap().len(), 64);
}

#[test]
fn an_unsupported_meta_version_is_32022_and_a_non_string_one_is_invalid_params() {
    let unsupported = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}}"#;
    assert_eq!(negotiate_with(&[], unsupported).unwrap_err().code, UNSUPPORTED_VERSION);
    let numeric = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":5}}}"#;
    assert_eq!(negotiate_with(&[], numeric).unwrap_err().code, INVALID_PARAMS);
}

#[test]
fn a_fully_formed_modern_call_selects_modern() {
    assert_eq!(negotiate_with(&modern_headers("get_car"), &modern_call("get_car")).unwrap(), Era::Modern);
}

#[test]
fn a_modern_header_without_meta_version_or_capabilities_is_invalid_params() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let h = [("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/list")];
    assert_eq!(negotiate_with(&h, body).unwrap_err().code, INVALID_PARAMS);
    let no_caps = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    assert_eq!(negotiate_with(&h, no_caps).unwrap_err().code, INVALID_PARAMS);
    let bad_caps = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}}"#;
    assert_eq!(negotiate_with(&h, bad_caps).unwrap_err().code, INVALID_PARAMS);
}

#[test]
fn a_modern_meta_version_without_the_header_or_with_a_different_one_is_a_header_mismatch() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    assert_eq!(negotiate_with(&[("mcp-method", "tools/list")], body).unwrap_err().code, HEADER_MISMATCH);
    assert_eq!(
        negotiate_with(&[("mcp-protocol-version", "2025-11-25"), ("mcp-method", "tools/list")], body)
            .unwrap_err()
            .code,
        HEADER_MISMATCH
    );
}

#[test]
fn a_missing_or_different_mcp_method_header_is_a_header_mismatch() {
    let body = modern_call("t");
    let no_method = [("mcp-protocol-version", "2026-07-28"), ("mcp-name", "t")];
    assert_eq!(negotiate_with(&no_method, &body).unwrap_err().code, HEADER_MISMATCH);
    let wrong = [("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/list"), ("mcp-name", "t")];
    assert_eq!(negotiate_with(&wrong, &body).unwrap_err().code, HEADER_MISMATCH);
}

#[test]
fn a_missing_or_different_mcp_name_on_tools_call_is_a_header_mismatch() {
    let body = modern_call("get_car");
    let missing = [("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/call")];
    assert_eq!(negotiate_with(&missing, &body).unwrap_err().code, HEADER_MISMATCH);
    assert_eq!(negotiate_with(&modern_headers("other"), &body).unwrap_err().code, HEADER_MISMATCH);
}

#[test]
fn mcp_name_is_not_required_for_methods_other_than_tools_call() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let h = [("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/list")];
    assert_eq!(negotiate_with(&h, body).unwrap(), Era::Modern);
}

#[test]
fn a_base64_sentinel_name_is_decoded_before_the_comparison() {
    let encoded = format!("=?base64?{}?=", base64::engine::general_purpose::STANDARD.encode("caf\u{e9}"));
    assert_eq!(negotiate_with(&modern_headers(&encoded), &modern_call("caf\u{e9}")).unwrap(), Era::Modern);
}

#[test]
fn a_malformed_base64_sentinel_or_one_that_decodes_to_invalid_utf8_is_a_header_mismatch() {
    let bad_b64 = "=?base64?!!!not base64!!!?=";
    assert_eq!(negotiate_with(&modern_headers(bad_b64), &modern_call(bad_b64)).unwrap_err().code, HEADER_MISMATCH);
    let invalid_utf8 = format!("=?base64?{}?=", base64::engine::general_purpose::STANDARD.encode([0xff, 0xfe, 0xfd]));
    assert_eq!(negotiate_with(&modern_headers(&invalid_utf8), &modern_call("x")).unwrap_err().code, HEADER_MISMATCH);
}

#[test]
fn a_header_value_over_1024_bytes_is_refused_without_being_decoded_even_when_it_would_match() {
    let long = "a".repeat(1025);
    assert_eq!(negotiate_with(&modern_headers(&long), &modern_call(&long)).unwrap_err().code, HEADER_MISMATCH);
    let long_sentinel = format!("=?base64?{}?=", base64::engine::general_purpose::STANDARD.encode("a".repeat(800)));
    assert!(long_sentinel.len() > 1024);
    assert_eq!(
        negotiate_with(&modern_headers(&long_sentinel), &modern_call(&"a".repeat(800))).unwrap_err().code,
        HEADER_MISMATCH
    );
}

#[test]
fn a_header_value_at_exactly_the_cap_still_matches() {
    let name = "a".repeat(1024);
    assert_eq!(negotiate_with(&modern_headers(&name), &modern_call(&name)).unwrap(), Era::Modern);
}

// ---- statuses and response shapes

#[test]
fn error_statuses_follow_the_era_table() {
    let status = |code: i32, era: Era| ProtoError::new(code, "m").into_response(era, None).status().as_u16();
    for code in [PARSE_ERROR, INVALID_REQUEST, INVALID_PARAMS] {
        assert_eq!(status(code, Era::Modern), 400, "{code} modern");
        assert_eq!(status(code, Era::Legacy), 200, "{code} legacy");
    }
    assert_eq!(status(METHOD_NOT_FOUND, Era::Modern), 404);
    assert_eq!(status(METHOD_NOT_FOUND, Era::Legacy), 200);
    for era in [Era::Modern, Era::Legacy] {
        assert_eq!(status(HEADER_MISMATCH, era), 400);
        assert_eq!(status(UNSUPPORTED_VERSION, era), 400);
    }
}

#[test]
fn provisional_era_is_modern_only_for_a_supported_modern_header() {
    assert_eq!(provisional_era(&headers(&[("mcp-protocol-version", "2026-07-28")])), Era::Modern);
    assert_eq!(provisional_era(&headers(&[("mcp-protocol-version", "2025-11-25")])), Era::Legacy);
    assert_eq!(provisional_era(&headers(&[("mcp-protocol-version", "garbage")])), Era::Legacy);
    assert_eq!(provisional_era(&HeaderMap::new()), Era::Legacy);
}

#[tokio::test]
async fn rpc_result_wraps_a_pre_serialised_result_and_echoes_the_raw_id() {
    let id = serde_json::value::to_raw_value(&serde_json::json!(12345678901234567890u64)).unwrap();
    let result = serde_json::value::to_raw_value(&serde_json::json!({ "a": 1 })).unwrap();
    let response = rpc_result(&id, &result);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        r#"{"jsonrpc":"2.0","id":12345678901234567890,"result":{"a":1}}"#
    );
}

#[tokio::test]
async fn the_generic_error_has_a_null_id_a_fixed_message_and_nothing_else() {
    let response = generic_error(StatusCode::FORBIDDEN, "Forbidden");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await,
        serde_json::json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "Forbidden" } })
    );
}

#[test]
fn a_notification_acknowledgement_is_202_with_no_body() {
    assert_eq!(accepted_no_content().status(), StatusCode::ACCEPTED);
}
