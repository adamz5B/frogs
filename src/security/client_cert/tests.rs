use super::*;
use crate::server::test_pki::*;
use chrono::TimeZone;

fn client_ca() -> Ca {
    Ca::root("identity test root")
}

fn identity_for(spec: &LeafSpec) -> ClientCertIdentity {
    let ca = client_ca();
    let leaf = build_leaf(&ca, spec);
    ClientCertIdentity::from_der(&leaf.der()).expect("a well-formed leaf should parse")
}

fn reject_reason(der: &[u8]) -> &'static str {
    ClientCertIdentity::from_der(der).expect_err("this certificate must be rejected").0
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fields() -> TestIdentityFields {
    TestIdentityFields::default()
}

fn from_fields(f: TestIdentityFields) -> ClientCertIdentity {
    ClientCertIdentity::from_test_fields(f)
}

// ---------------------------------------------------------------------
// ClientCertIdentity::from_der
// ---------------------------------------------------------------------

#[test]
fn every_field_of_a_valid_leaf_is_extracted() {
    let spec = LeafSpec::valid();
    let ca = client_ca();
    let leaf = build_leaf(&ca, &spec);
    let der = leaf.der();
    let id = ClientCertIdentity::from_der(&der).unwrap();

    assert_eq!(id.cn.as_deref(), Some("client.example.com"));
    assert_eq!(id.subject, "CN=client.example.com");
    assert_eq!(id.issuer, "CN=identity test root");
    assert_eq!(id.serial, hex_of(&spec.serial));
    assert_eq!(id.not_before.unwrap().timestamp(), spec.not_before);
    assert_eq!(id.not_after.unwrap().timestamp(), spec.not_after);
    assert_eq!(id.san_dns, vec!["a.svc.example", "b.svc.example", "orders.internal.example.com"]);
    assert_eq!(id.san_uri, vec!["spiffe://example.org/ns/a", "spiffe://example.org/ns/orders"]);
    assert_eq!(id.san_email, vec!["first@example.com", "Alice@Example.com"]);
}

#[test]
fn the_fingerprint_is_the_lowercase_hex_sha256_of_the_leaf_der() {
    let ca = client_ca();
    let leaf = build_leaf(&ca, &LeafSpec::valid());
    let der = leaf.der();
    let id = ClientCertIdentity::from_der(&der).unwrap();

    let independent = ring::digest::digest(&ring::digest::SHA256, &der);
    assert_eq!(id.fingerprint(), hex_of(independent.as_ref()));
    assert_eq!(id.fingerprint().len(), 64);
    assert_eq!(id.fingerprint(), id.fingerprint().to_ascii_lowercase());
}

#[test]
fn two_different_certificates_have_different_fingerprints() {
    let a = identity_for(&LeafSpec::valid());
    let b = identity_for(&LeafSpec::valid());
    assert_ne!(a.fingerprint(), b.fingerprint());
}

#[test]
fn a_certificate_with_no_common_name_has_a_null_cn() {
    let id = identity_for(&LeafSpec {
        cn: Vec::new(),
        extra_dn: vec![(rcgen::DnType::OrganizationName, "Acme".into())],
        ..LeafSpec::valid()
    });
    assert_eq!(id.cn, None);
    assert_eq!(id.subject, "O=Acme");
    assert_eq!(id.to_json()["cn"], Value::Null);
}

#[test]
fn a_certificate_with_two_common_names_has_a_null_cn_but_both_appear_in_the_subject() {
    let id = identity_for(&LeafSpec {
        cn: vec!["first.example".into(), "second.example".into()],
        ..LeafSpec::valid()
    });
    assert_eq!(id.cn, None, "an ambiguous CN must never be picked arbitrarily");
    assert!(id.subject.contains("CN=first.example"), "{}", id.subject);
    assert!(id.subject.contains("CN=second.example"), "{}", id.subject);
}

#[test]
fn a_certificate_with_no_sans_has_empty_arrays_not_nulls() {
    let id = identity_for(&LeafSpec::bare());
    assert!(id.san_dns.is_empty() && id.san_uri.is_empty() && id.san_email.is_empty());
    let json = id.to_json();
    assert_eq!(json["san"]["dns"], serde_json::json!([]));
    assert_eq!(json["san"]["uri"], serde_json::json!([]));
    assert_eq!(json["san"]["email"], serde_json::json!([]));
}

#[test]
fn san_entries_keep_certificate_order() {
    let id = identity_for(&LeafSpec {
        dns: vec!["z.example".into(), "a.example".into(), "m.example".into()],
        ..LeafSpec::valid()
    });
    assert_eq!(id.san_dns, vec!["z.example", "a.example", "m.example"]);
}

#[test]
fn a_non_ascii_subject_is_preserved() {
    let id = identity_for(&LeafSpec {
        cn: vec!["Zoë Müller".into()],
        ..LeafSpec::valid()
    });
    assert_eq!(id.cn.as_deref(), Some("Zoë Müller"));
    assert_eq!(id.subject, "CN=Zoë Müller");
}

#[test]
fn a_high_bit_serial_is_rendered_without_der_sign_padding() {
    let id = identity_for(&LeafSpec {
        serial: vec![0xff, 0x01, 0x02],
        ..LeafSpec::valid()
    });
    assert_eq!(id.serial, "ff0102");
}

#[test]
fn a_serial_with_explicit_leading_zero_bytes_is_stripped_to_its_magnitude() {
    let subject = name(&[rdn(&[utf8_atv(OID_CN, "raw")])]);
    let der = raw_cert(subject.clone(), subject.clone(), &[0x00, 0x00, 0x80], &[], now_unix() - DAY, now_unix() + DAY);
    assert_eq!(ClientCertIdentity::from_der(&der).unwrap().serial, "80");

    let zero = raw_cert(subject.clone(), subject, &[0x00], &[], now_unix() - DAY, now_unix() + DAY);
    assert_eq!(
        ClientCertIdentity::from_der(&zero).unwrap().serial,
        "00",
        "an all-zero serial still renders one digit pair"
    );
}

fn subject_of(rdns: &[Vec<u8>]) -> String {
    let der = raw_cert_with_subject(name(rdns));
    ClientCertIdentity::from_der(&der).unwrap().subject
}

#[test]
fn rfc4514_rdns_are_rendered_most_specific_first() {
    let rendered = subject_of(&[rdn(&[utf8_atv(OID_O, "Org")]), rdn(&[utf8_atv(OID_OU, "Unit")]), rdn(&[utf8_atv(OID_CN, "leaf")])]);
    assert_eq!(rendered, "CN=leaf,OU=Unit,O=Org");
}

#[test]
fn rfc4514_special_characters_are_backslash_escaped_anywhere() {
    let rendered = subject_of(&[rdn(&[utf8_atv(OID_O, "a,b+c\"d\\e<f>g;h")])]);
    assert_eq!(rendered, "O=a\\,b\\+c\\\"d\\\\e\\<f\\>g\\;h");
}

#[test]
fn rfc4514_a_leading_hash_or_space_and_a_trailing_space_are_escaped() {
    assert_eq!(subject_of(&[rdn(&[utf8_atv(OID_O, "#hash")])]), "O=\\#hash");
    assert_eq!(subject_of(&[rdn(&[utf8_atv(OID_O, " lead")])]), "O=\\ lead");
    assert_eq!(subject_of(&[rdn(&[utf8_atv(OID_O, "trail ")])]), "O=trail\\ ");
    assert_eq!(
        subject_of(&[rdn(&[utf8_atv(OID_O, "mid#dle sp ace")])]),
        "O=mid#dle sp ace",
        "only leading # / space and trailing space are special"
    );
}

#[test]
fn rfc4514_a_multi_valued_rdn_is_joined_with_plus_in_der_order() {
    let rendered = subject_of(&[rdn(&[utf8_atv(OID_O, "Org")]), rdn(&[utf8_atv(OID_CN, "leaf"), utf8_atv(OID_OU, "Unit")])]);
    assert_eq!(rendered, "CN=leaf+OU=Unit,O=Org");
}

#[test]
fn rfc4514_a_non_string_value_is_rendered_as_hash_hex_der() {
    // OCTET STRING (tag 0x04) holding de ad — not a string type.
    let rendered = subject_of(&[rdn(&[atv(OID_O, 0x04, &[0xde, 0xad])])]);
    assert_eq!(rendered, "O=#0402dead");
}

#[test]
fn rfc4514_unknown_oids_render_as_dotted_oids_and_known_ones_by_short_name() {
    let rendered = subject_of(&[
        rdn(&[utf8_atv(&[2, 5, 4, 5], "serial-attr")]),
        rdn(&[utf8_atv(&[2, 5, 4, 9], "1 Main St")]),
        rdn(&[utf8_atv(&[2, 5, 4, 6], "US")]),
    ]);
    assert_eq!(rendered, "C=US,STREET=1 Main St,2.5.4.5=serial-attr");
}

#[test]
fn the_issuer_is_rendered_with_the_same_rules_as_the_subject() {
    let subject = name(&[rdn(&[utf8_atv(OID_CN, "leaf")])]);
    let issuer = name(&[rdn(&[utf8_atv(OID_O, "Ca,Inc")]), rdn(&[utf8_atv(OID_CN, "Root")])]);
    let der = raw_cert(subject, issuer, &[1], &[], now_unix() - DAY, now_unix() + DAY);
    assert_eq!(ClientCertIdentity::from_der(&der).unwrap().issuer, "CN=Root,O=Ca\\,Inc");
}

// ----- caps: exactly at the limit accepted, one over rejected -----

#[test]
fn sixty_four_sans_are_accepted_and_sixty_five_rejected() {
    let ca = client_ca();
    let ok = build_leaf(&ca, &LeafSpec::with_dns_count(64));
    assert_eq!(ClientCertIdentity::from_der(&ok.der()).unwrap().san_dns.len(), 64);

    let over = build_leaf(&ca, &LeafSpec::with_dns_count(65));
    assert!(reject_reason(&over.der()).contains("too many subjectAltName"));
}

#[test]
fn the_san_cap_counts_entries_across_every_kind_not_per_kind() {
    let ca = client_ca();
    let spec = LeafSpec {
        dns: (0..30).map(|i| format!("d{i}.example")).collect(),
        uri: (0..30).map(|i| format!("spiffe://x/{i}")).collect(),
        email: (0..5).map(|i| format!("e{i}@example.com")).collect(),
        ..LeafSpec::valid()
    };
    let leaf = build_leaf(&ca, &spec);
    assert!(reject_reason(&leaf.der()).contains("too many subjectAltName"), "65 mixed entries must exceed the cap");
}

#[test]
fn a_1024_byte_san_value_is_accepted_and_1025_rejected() {
    let ca = client_ca();
    let ok = build_leaf(
        &ca,
        &LeafSpec {
            dns: vec!["a".repeat(1024)],
            ..LeafSpec::valid()
        },
    );
    assert_eq!(ClientCertIdentity::from_der(&ok.der()).unwrap().san_dns[0].len(), 1024);

    let over = build_leaf(
        &ca,
        &LeafSpec {
            dns: vec!["a".repeat(1025)],
            ..LeafSpec::valid()
        },
    );
    assert!(reject_reason(&over.der()).contains("oversized"));
}

#[test]
fn a_1024_byte_cn_is_accepted_and_1025_rejected() {
    let ca = client_ca();
    let ok = build_leaf(
        &ca,
        &LeafSpec {
            cn: vec!["c".repeat(1024)],
            ..LeafSpec::valid()
        },
    );
    assert_eq!(ClientCertIdentity::from_der(&ok.der()).unwrap().cn.unwrap().len(), 1024);

    let over = build_leaf(
        &ca,
        &LeafSpec {
            cn: vec!["c".repeat(1025)],
            ..LeafSpec::valid()
        },
    );
    assert!(reject_reason(&over.der()).contains("oversized"));
}

#[test]
fn a_rendered_dn_of_exactly_4096_bytes_is_accepted_and_4097_rejected() {
    // "O=" + value, so a 4094-byte value renders to exactly 4096 bytes.
    let at_limit = raw_cert_with_subject(name(&[rdn(&[utf8_atv(OID_O, &"o".repeat(4094))])]));
    assert_eq!(ClientCertIdentity::from_der(&at_limit).unwrap().subject.len(), 4096);

    let over = raw_cert_with_subject(name(&[rdn(&[utf8_atv(OID_O, &"o".repeat(4095))])]));
    assert!(reject_reason(&over).contains("oversized"));
}

#[test]
fn a_dn_made_of_many_small_attributes_is_capped_on_its_total_rendered_size() {
    let rdns: Vec<Vec<u8>> = (0..6).map(|_| rdn(&[utf8_atv(OID_OU, &"u".repeat(900))])).collect();
    let der = raw_cert_with_subject(name(&rdns));
    assert!(reject_reason(&der).contains("oversized"));
}

#[test]
fn a_leaf_der_of_exactly_16_kib_is_accepted_and_one_byte_over_rejected() {
    let subject = name(&[rdn(&[utf8_atv(OID_CN, "big")])]);
    let build = |pad: usize| {
        // A non-critical extension with an unknown OID, used purely as padding.
        let mut ext = oid_der(&[1, 3, 6, 1, 4, 1, 99999, 1]);
        ext.extend(tlv(0x04, &vec![0u8; pad]));
        raw_cert(subject.clone(), subject.clone(), &[1], &[tlv(0x30, &ext)], now_unix() - DAY, now_unix() + DAY)
    };
    let mut pad = 15_000usize;
    while build(pad).len() < MAX_LEAF_DER_BYTES {
        pad += 1;
    }
    let at_limit = build(pad);
    assert_eq!(at_limit.len(), MAX_LEAF_DER_BYTES, "padding search should land exactly on the limit");
    assert!(ClientCertIdentity::from_der(&at_limit).is_ok());

    let over = build(pad + 1);
    assert_eq!(over.len(), MAX_LEAF_DER_BYTES + 1);
    assert!(reject_reason(&over).contains("too large"));
}

// ----- control characters / encoding -----

#[test]
fn control_characters_in_a_cn_are_rejected() {
    let ca = client_ca();
    for bad in ["a\u{0}b", "a\u{1}b", "a\u{1f}b", "a\u{7f}b", "a\u{80}b", "a\u{85}b", "a\u{9f}b"] {
        let leaf = build_leaf(
            &ca,
            &LeafSpec {
                cn: vec![bad.to_string()],
                ..LeafSpec::valid()
            },
        );
        assert!(reject_reason(&leaf.der()).contains("control character"), "CN {bad:?} must be rejected");
    }
}

#[test]
fn the_characters_just_outside_the_control_ranges_are_accepted() {
    let ca = client_ca();
    for ok in ["a b", "a\u{20}b", "a\u{a0}b", "a~b"] {
        let leaf = build_leaf(
            &ca,
            &LeafSpec {
                cn: vec![ok.to_string()],
                ..LeafSpec::valid()
            },
        );
        assert!(ClientCertIdentity::from_der(&leaf.der()).is_ok(), "CN {ok:?} should be accepted");
    }
}

#[test]
fn control_characters_in_a_non_cn_subject_attribute_are_rejected() {
    let der = raw_cert_with_subject(name(&[rdn(&[utf8_atv(OID_O, "Or\u{1}g")]), rdn(&[utf8_atv(OID_CN, "ok")])]));
    assert!(reject_reason(&der).contains("control character"));
}

#[test]
fn control_characters_in_the_issuer_are_rejected() {
    let subject = name(&[rdn(&[utf8_atv(OID_CN, "ok")])]);
    let issuer = name(&[rdn(&[utf8_atv(OID_CN, "bad\u{1}issuer")])]);
    let der = raw_cert(subject, issuer, &[1], &[], now_unix() - DAY, now_unix() + DAY);
    assert!(reject_reason(&der).contains("control character"));
}

#[test]
fn control_characters_in_a_san_value_are_rejected() {
    let subject = name(&[rdn(&[utf8_atv(OID_CN, "ok")])]);
    for (tag, value) in [
        (0x82u8, b"a\x01b.example".to_vec()),
        (0x86, b"spiffe://a\x7fb".to_vec()),
        (0x81, b"a\x01@example.com".to_vec()),
    ] {
        let der = raw_cert(
            subject.clone(),
            subject.clone(),
            &[1],
            &[raw_san_extension(&[(tag, value)])],
            now_unix() - DAY,
            now_unix() + DAY,
        );
        assert!(ClientCertIdentity::from_der(&der).is_err(), "SAN tag {tag:#x} with a control char must be rejected");
    }
}

#[test]
fn a_non_ascii_dns_name_san_is_rejected() {
    let subject = name(&[rdn(&[utf8_atv(OID_CN, "ok")])]);
    let der = raw_cert(
        subject.clone(),
        subject,
        &[1],
        &[raw_san_extension(&[(0x82, "caf\u{e9}.example".as_bytes().to_vec())])],
        now_unix() - DAY,
        now_unix() + DAY,
    );
    assert!(
        ClientCertIdentity::from_der(&der).is_err(),
        "an IA5String dNSName holding UTF-8 must never reach a matcher"
    );
}

#[test]
fn a_san_containing_a_space_is_rejected() {
    let subject = name(&[rdn(&[utf8_atv(OID_CN, "ok")])]);
    let der = raw_cert(
        subject.clone(),
        subject,
        &[1],
        &[raw_san_extension(&[(0x82, b"a b.example".to_vec())])],
        now_unix() - DAY,
        now_unix() + DAY,
    );
    assert!(reject_reason(&der).contains("non-ASCII or space"));
}

#[test]
fn an_ip_san_is_ignored_not_rejected() {
    let ca = client_ca();
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![
        rcgen::SanType::IpAddress("10.0.0.1".parse().unwrap()),
        rcgen::SanType::DnsName("only.example".try_into().unwrap()),
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    let id = ClientCertIdentity::from_der(cert.der()).unwrap();
    assert_eq!(id.san_dns, vec!["only.example"]);
    assert!(id.san_uri.is_empty() && id.san_email.is_empty());
}

#[test]
fn garbage_and_empty_input_are_rejected_without_panicking() {
    assert!(ClientCertIdentity::from_der(&[]).is_err());
    assert!(ClientCertIdentity::from_der(b"not a certificate").is_err());
    let ca = client_ca();
    let mut der = build_leaf(&ca, &LeafSpec::valid()).der();
    der.truncate(der.len() / 2);
    assert!(ClientCertIdentity::from_der(&der).is_err());
}

#[test]
fn rejection_messages_never_echo_certificate_content() {
    let ca = client_ca();
    let leaf = build_leaf(
        &ca,
        &LeafSpec {
            cn: vec!["secret-cn\u{1}".to_string()],
            ..LeafSpec::valid()
        },
    );
    let err = ClientCertIdentity::from_der(&leaf.der()).unwrap_err();
    assert!(!err.to_string().contains("secret-cn"));
}

// ----- is_valid_at / Debug / JSON -----

#[test]
fn is_valid_at_is_inclusive_of_not_before_and_exclusive_of_not_after() {
    let id = identity_for(&LeafSpec::valid());
    let (nb, na) = (id.not_before.unwrap(), id.not_after.unwrap());
    let second = chrono::Duration::seconds(1);
    assert!(!id.is_valid_at(nb - second));
    assert!(id.is_valid_at(nb));
    assert!(id.is_valid_at(nb + second));
    assert!(id.is_valid_at(na - second));
    assert!(!id.is_valid_at(na), "the instant of notAfter is already expired");
    assert!(!id.is_valid_at(na + second));
}

#[test]
fn an_identity_with_no_bounds_is_valid_at_any_time() {
    let id = from_fields(fields());
    assert!(id.is_valid_at(chrono::Utc.timestamp_opt(0, 0).unwrap()));
    assert!(id.is_valid_at(chrono::Utc.timestamp_opt(4_000_000_000, 0).unwrap()));
}

#[test]
fn a_test_identity_with_only_not_after_enforces_just_that_bound() {
    let na = chrono::Utc.timestamp_opt(2_000_000_000, 0).unwrap();
    let id = from_fields(TestIdentityFields { not_after: Some(na), ..fields() });
    assert!(id.is_valid_at(na - chrono::Duration::seconds(1)));
    assert!(!id.is_valid_at(na));
}

#[test]
fn debug_output_leaks_no_cn_san_serial_or_fingerprint() {
    let id = identity_for(&LeafSpec::valid());
    let debug = format!("{id:?}");
    for secret in [
        "client.example.com",
        "a.svc.example",
        "spiffe",
        "first@example.com",
        id.fingerprint(),
        &id.serial,
        "frogs",
    ] {
        assert!(!debug.contains(secret), "Debug leaked {secret:?}: {debug}");
    }
    let wrapped = format!("{:?}", Some(std::sync::Arc::new(id)));
    assert!(!wrapped.contains("client.example.com"));
}

#[test]
fn to_json_nests_sans_under_san_and_round_trips_through_from_identity_json() {
    let id = identity_for(&LeafSpec::valid());
    let json = id.to_json();
    assert_eq!(json["cn"], "client.example.com");
    assert_eq!(json["fingerprint"], id.fingerprint());
    assert_eq!(json["san"]["dns"][2], "orders.internal.example.com");
    assert_eq!(json["san"]["uri"][1], "spiffe://example.org/ns/orders");
    assert!(json["notAfter"].as_str().unwrap().ends_with('Z'));

    let back = ClientCertIdentity::from_identity_json(&json).unwrap();
    assert_eq!(back.san_dns, id.san_dns);
    assert_eq!(back.san_uri, id.san_uri);
    assert_eq!(back.san_email, id.san_email);
    assert_eq!(back.cn, id.cn);
    assert_eq!(back.fingerprint, id.fingerprint);
    assert_eq!(back.not_after, id.not_after);
}

#[test]
fn from_identity_json_accepts_a_scalar_or_an_array_for_each_san_kind() {
    let one = ClientCertIdentity::from_identity_json(&serde_json::json!({ "san": { "dns": "a.example" } })).unwrap();
    assert_eq!(one.san_dns, vec!["a.example"]);
    let many = ClientCertIdentity::from_identity_json(&serde_json::json!({ "san": { "dns": ["a.example", "b.example"] } })).unwrap();
    assert_eq!(many.san_dns, vec!["a.example", "b.example"]);
}

#[test]
fn from_identity_json_rejects_shape_mismatches() {
    for bad in [
        serde_json::json!("a string"),
        serde_json::json!([1, 2]),
        serde_json::json!({ "cn": 5 }),
        serde_json::json!({ "san": "x" }),
        serde_json::json!({ "san": { "dns": 5 } }),
        serde_json::json!({ "san": { "dns": [1] } }),
        serde_json::json!({ "notAfter": "not a date" }),
    ] {
        assert!(ClientCertIdentity::from_identity_json(&bad).is_none(), "{bad} should be rejected");
    }
}

#[test]
fn bind_value_returns_text_or_null_and_none_for_sans() {
    let id = identity_for(&LeafSpec::valid());
    assert_eq!(id.bind_value(CertField::Cn), Some(SqlValue::Text("client.example.com".into())));
    assert_eq!(id.bind_value(CertField::Fingerprint), Some(SqlValue::Text(id.fingerprint().to_string())));
    assert_eq!(id.bind_value(CertField::Serial), Some(SqlValue::Text(id.serial.clone())));
    assert!(matches!(id.bind_value(CertField::NotAfter), Some(SqlValue::Text(_))));
    for san in [CertField::SanDns, CertField::SanUri, CertField::SanEmail] {
        assert_eq!(id.bind_value(san), None);
    }

    let empty = from_fields(fields());
    assert_eq!(empty.bind_value(CertField::Cn), Some(SqlValue::Null));
    assert_eq!(empty.bind_value(CertField::Subject), Some(SqlValue::Null));
    assert_eq!(empty.bind_value(CertField::Fingerprint), Some(SqlValue::Null));
    assert_eq!(empty.bind_value(CertField::NotAfter), Some(SqlValue::Null));
}

#[test]
fn cert_field_parses_every_documented_name_and_only_those() {
    for (name, field) in [
        ("cn", CertField::Cn),
        ("subject", CertField::Subject),
        ("issuer", CertField::Issuer),
        ("serial", CertField::Serial),
        ("fingerprint", CertField::Fingerprint),
        ("notAfter", CertField::NotAfter),
        ("san.dns", CertField::SanDns),
        ("san.uri", CertField::SanUri),
        ("san.email", CertField::SanEmail),
    ] {
        assert_eq!(CertField::parse(name), Some(field));
    }
    for bad in ["foo", "CN", "notafter", "san", "san.ip", "", "cert.cn"] {
        assert_eq!(CertField::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn only_the_san_fields_are_not_bindable() {
    for f in [
        CertField::Cn,
        CertField::Subject,
        CertField::Issuer,
        CertField::Serial,
        CertField::Fingerprint,
        CertField::NotAfter,
    ] {
        assert!(f.is_bindable());
    }
    for f in [CertField::SanDns, CertField::SanUri, CertField::SanEmail] {
        assert!(!f.is_bindable());
    }
}

#[test]
fn from_test_fields_normalizes_hex_but_leaves_non_hex_untouched() {
    let id = from_fields(TestIdentityFields {
        serial: Some("AB:CD".into()),
        fingerprint: Some("not hex".into()),
        ..fields()
    });
    assert_eq!(id.serial, "abcd");
    assert_eq!(id.fingerprint, "not hex");
}

#[test]
fn leaf_client_auth_eku_distinguishes_present_wrong_and_absent() {
    let ca = client_ca();
    assert_eq!(leaf_client_auth_eku(&build_leaf(&ca, &LeafSpec::valid()).der()).unwrap(), Some(true));
    assert_eq!(leaf_client_auth_eku(&build_leaf(&ca, &LeafSpec::server_auth_only()).der()).unwrap(), Some(false));
    assert_eq!(leaf_client_auth_eku(&build_leaf(&ca, &LeafSpec::no_eku()).der()).unwrap(), None);
    assert!(leaf_client_auth_eku(b"garbage").is_err());
}

// ---------------------------------------------------------------------
// MtlsCondition
// ---------------------------------------------------------------------

fn cond(expr: &str) -> MtlsCondition {
    MtlsCondition::compile(expr).unwrap_or_else(|e| panic!("{expr:?} should compile: {e}"))
}

fn valid_identity() -> ClientCertIdentity {
    identity_for(&LeafSpec::valid())
}

#[test]
fn a_san_condition_matches_the_first_second_and_third_dns_entry() {
    let id = valid_identity();
    assert!(cond("cert.san.dns = a.svc.example").matches(&id));
    assert!(cond("cert.san.dns = b.svc.example").matches(&id));
    assert!(cond("cert.san.dns = orders.internal.example.com").matches(&id), "any-of must reach the third SAN");
}

#[test]
fn a_san_condition_matches_the_second_uri_entry() {
    let id = valid_identity();
    assert!(cond("cert.san.uri = spiffe://example.org/ns/orders").matches(&id));
    assert!(cond("cert.san.uri = spiffe://example.org/ns/a").matches(&id));
}

#[test]
fn a_san_condition_matches_either_email() {
    let id = valid_identity();
    assert!(cond("cert.san.email = first@example.com").matches(&id));
    assert!(cond("cert.san.email = Alice@Example.com").matches(&id));
}

#[test]
fn an_empty_san_list_or_no_matching_entry_is_false() {
    let bare = identity_for(&LeafSpec::bare());
    assert!(!cond("cert.san.dns = a.svc.example").matches(&bare));
    assert!(!cond("cert.san.uri = spiffe://example.org/ns/a").matches(&bare));
    assert!(!cond("cert.san.email = first@example.com").matches(&bare));
    assert!(!cond("cert.san.dns = nope.example").matches(&valid_identity()));
}

#[test]
fn san_matching_is_whole_value_only_never_substring_prefix_or_superstring() {
    let id = valid_identity();
    for expected in [
        "a.svc",
        "svc.example",
        "xa.svc.example",
        "a.svc.example.evil.com",
        "internal.example.com",
        "orders.internal.example.co",
        "a",
    ] {
        assert!(
            !cond(&format!("cert.san.dns = {expected}")).matches(&id),
            "{expected} must not match by substring/prefix/superstring"
        );
    }
    assert!(!cond("cert.san.uri = spiffe://example.org/ns").matches(&id));
    assert!(!cond("cert.san.uri = spiffe://example.org/ns/orders/x").matches(&id));
}

#[test]
fn dns_matching_ignores_ascii_case_and_a_single_trailing_dot_on_either_side() {
    let id = valid_identity();
    assert!(cond("cert.san.dns = A.SVC.Example").matches(&id));
    assert!(cond("cert.san.dns = a.svc.example.").matches(&id), "trailing dot on the expected side");

    let dotted = from_fields(TestIdentityFields {
        san_dns: vec!["Host.Example.".into()],
        ..fields()
    });
    assert!(cond("cert.san.dns = host.example").matches(&dotted), "trailing dot on the presented side");
    assert!(cond("cert.san.dns = HOST.EXAMPLE.").matches(&dotted), "trailing dot on both sides");

    let double = from_fields(TestIdentityFields {
        san_dns: vec!["host.example..".into()],
        ..fields()
    });
    assert!(!cond("cert.san.dns = host.example").matches(&double), "only one trailing dot is ignored");
}

#[test]
fn wildcards_are_literal_in_both_directions() {
    let wild_cert = from_fields(TestIdentityFields {
        san_dns: vec!["*.svc.example".into()],
        ..fields()
    });
    assert!(!cond("cert.san.dns = a.svc.example").matches(&wild_cert), "a presented wildcard must not expand");
    assert!(
        cond("cert.san.dns = *.svc.example").matches(&wild_cert),
        "a literal expected wildcard equals the literal presented one"
    );

    let plain = valid_identity();
    assert!(
        !cond("cert.san.dns = *.svc.example").matches(&plain),
        "an expected wildcard must not expand over presented names"
    );
}

#[test]
fn uri_matching_is_exact_including_scheme_case_path_case_and_trailing_slash() {
    let id = valid_identity();
    assert!(!cond("cert.san.uri = SPIFFE://example.org/ns/a").matches(&id));
    assert!(!cond("cert.san.uri = spiffe://example.org/NS/a").matches(&id));
    assert!(!cond("cert.san.uri = spiffe://EXAMPLE.org/ns/a").matches(&id));
    assert!(!cond("cert.san.uri = spiffe://example.org/ns/a/").matches(&id));
}

#[test]
fn email_matching_is_exact_on_the_local_part_and_case_insensitive_on_the_domain() {
    let id = valid_identity();
    assert!(cond("cert.san.email = first@EXAMPLE.COM").matches(&id), "domain case-insensitive");
    assert!(!cond("cert.san.email = First@example.com").matches(&id), "local part is case-sensitive");
    assert!(!cond("cert.san.email = alice@example.com").matches(&id), "local part case differs from Alice");
    assert!(cond("cert.san.email = Alice@example.com").matches(&id));
    assert!(!cond("cert.san.email = first@example.org").matches(&id));
    assert!(!cond("cert.san.email = first@mail.example.com").matches(&id));
}

#[test]
fn a_presented_email_with_an_empty_local_part_or_domain_never_matches() {
    let id = from_fields(TestIdentityFields {
        san_email: vec!["@example.com".into(), "user@".into(), "noat".into()],
        ..fields()
    });
    assert!(!cond("cert.san.email = x@example.com").matches(&id));
    assert!(!cond("cert.san.email = user@example.com").matches(&id));
    assert!(!cond("cert.san.email = noat@noat").matches(&id));
}

#[test]
fn email_splits_at_the_last_at_sign() {
    let id = from_fields(TestIdentityFields {
        san_email: vec!["a@b@Example.com".into()],
        ..fields()
    });
    assert!(cond("cert.san.email = a@b@example.com").matches(&id));
    assert!(!cond("cert.san.email = a@example.com").matches(&id));
}

#[test]
fn hex_fields_ignore_case_and_colons_in_the_expected_value() {
    let id = valid_identity();
    let fp = id.fingerprint().to_string();
    assert!(cond(&format!("cert.fingerprint = {}", fp.to_uppercase())).matches(&id));
    let colons = fp
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap().to_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    assert!(cond(&format!("cert.fingerprint = {colons}")).matches(&id));
    let other_last = if fp.ends_with('0') { '1' } else { '0' };
    assert!(!cond(&format!("cert.fingerprint = {}{other_last}", &fp[..63])).matches(&id));
    assert!(cond(&format!("cert.serial = {}", id.serial.to_uppercase())).matches(&id));
}

#[test]
fn the_expected_value_is_raw_text_so_a_leading_zero_hex_serial_is_not_an_integer() {
    let padded = from_fields(TestIdentityFields {
        serial: Some("0012".into()),
        ..fields()
    });
    let unpadded = from_fields(TestIdentityFields {
        serial: Some("12".into()),
        ..fields()
    });
    let c = cond("cert.serial = 0012");
    assert!(c.matches(&padded), "'0012' stays text");
    assert!(!c.matches(&unpadded), "'0012' must not be parsed as the integer 12");
}

#[test]
fn quoted_and_unquoted_right_hand_sides_compile_identically() {
    assert_eq!(cond("cert.cn = foo.example"), cond("cert.cn = \"foo.example\""));
    assert_eq!(cond("cert.san.dns = a.example"), cond("cert.san.dns = \"a.example\""));
    // Only one surrounding pair is stripped.
    let id = from_fields(TestIdentityFields {
        cn: Some("\"x\"".into()),
        ..fields()
    });
    assert!(cond("cert.cn = \"\"x\"\"").matches(&id));
}

#[test]
fn scalar_fields_match_exactly_and_a_missing_cn_never_matches() {
    let id = valid_identity();
    assert!(cond("cert.cn = client.example.com").matches(&id));
    assert!(!cond("cert.cn = Client.example.com").matches(&id));
    assert!(cond("cert.subject = CN=client.example.com").matches(&id));
    assert!(cond("cert.issuer = CN=identity test root").matches(&id));
    assert!(!cond("cert.cn = anything").matches(&from_fields(fields())));
}

#[test]
fn not_after_matches_the_rfc3339_rendering() {
    let id = valid_identity();
    let rendered = id.not_after.unwrap().to_rfc3339_opts(SecondsFormat::Secs, true);
    assert!(cond(&format!("cert.notAfter = {rendered}")).matches(&id));
    assert!(!cond("cert.notAfter = 2001-01-01T00:00:00Z").matches(&id));
}

#[test]
fn compile_rejects_a_wrong_label_unknown_field_and_empty_or_missing_values() {
    for bad in [
        "row.cn = x",
        "response.san.dns = x",
        "cert.foo = x",
        "cert.san.ip = x",
        "cert.cn =",
        "cert.cn = \"\"",
        "cert.cn",
        "cert = x",
        "",
        "cert.san.dns = .",
    ] {
        assert!(MtlsCondition::compile(bad).is_err(), "{bad:?} should fail to compile");
    }
}

#[test]
fn compile_rejects_a_non_ascii_dns_expectation_but_accepts_an_a_label() {
    assert!(MtlsCondition::compile("cert.san.dns = caf\u{e9}.example").is_err());
    assert!(MtlsCondition::compile("cert.san.dns = xn--caf-dma.example").is_ok());
}

#[test]
fn compile_rejects_malformed_email_expectations() {
    for bad in ["cert.san.email = noat", "cert.san.email = @example.com", "cert.san.email = user@"] {
        assert!(MtlsCondition::compile(bad).is_err(), "{bad:?}");
    }
    assert!(MtlsCondition::compile("cert.san.email = user@example.com").is_ok());
}

#[test]
fn compile_rejects_malformed_hex_for_serial_and_fingerprint() {
    for bad in ["cert.serial = xyz", "cert.fingerprint = 12g4", "cert.serial = :::", "cert.fingerprint = ab cd"] {
        assert!(MtlsCondition::compile(bad).is_err(), "{bad:?}");
    }
    assert!(MtlsCondition::compile("cert.serial = 0A:0b").is_ok());
}

#[test]
fn a_condition_with_an_equals_sign_inside_a_uri_still_compiles() {
    let c = cond("cert.san.uri = https://x.example/a?b=c");
    let id = from_fields(TestIdentityFields {
        san_uri: vec!["https://x.example/a?b=c".into()],
        ..fields()
    });
    assert!(c.matches(&id));
}
