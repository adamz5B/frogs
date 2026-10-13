use super::*;
use crate::server::test_pki::*;
use std::sync::Mutex;

// ---------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------

fn client_auth_cfg(json: &str) -> ClientAuthConfig {
    serde_json::from_str(json).unwrap_or_else(|e| panic!("{json}: {e}"))
}

struct Built {
    verifier: Arc<dyn ClientCertVerifier>,
    next_updates: Vec<(PathBuf, DateTime<Utc>)>,
    warnings: Vec<String>,
}

fn try_build_verifier(dir: &Path, json: &str) -> io::Result<Built> {
    ensure_crypto_provider();
    let mut next_updates = Vec::new();
    let mut warnings = Vec::new();
    let verifier = build_client_verifier(&client_auth_cfg(json), dir, &mut next_updates, &mut warnings)?;
    Ok(Built {
        verifier,
        next_updates,
        warnings,
    })
}

fn build_verifier(dir: &Path, json: &str) -> Built {
    try_build_verifier(dir, json).expect("verifier should build")
}

fn verify(verifier: &Arc<dyn ClientCertVerifier>, leaf: &Leaf, intermediates: &[&Ca]) -> Result<ClientCertVerified, rustls::Error> {
    let end_entity = CertificateDer::from(leaf.der());
    let chain: Vec<CertificateDer<'static>> = intermediates.iter().map(|ca| CertificateDer::from(ca.cert.der().to_vec())).collect();
    verifier.verify_client_cert(&end_entity, &chain, UnixTime::now())
}

fn dir_with_ca(ca: &Ca) -> PathBuf {
    let dir = temp_dir("tls-unit");
    std::fs::write(dir.join("client-ca.pem"), ca.pem()).unwrap();
    dir
}

const REQUIRED: &str = r#"{ "mode": "required", "caPath": "client-ca.pem" }"#;
const OPTIONAL: &str = r#"{ "mode": "optional", "caPath": "client-ca.pem" }"#;

fn is_cert_error(result: &Result<ClientCertVerified, rustls::Error>, wanted: impl Fn(&CertificateError) -> bool) -> bool {
    matches!(result, Err(rustls::Error::InvalidCertificate(e)) if wanted(e))
}

// ---------------------------------------------------------------------
// build_server_config / loading errors
// ---------------------------------------------------------------------

#[test]
fn a_missing_ca_file_is_an_error_naming_the_file() {
    let dir = temp_dir("tls-unit");
    let err = try_build_verifier(&dir, r#"{ "mode": "required", "caPath": "no-such-ca.pem" }"#)
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("no-such-ca.pem"), "{err}");
}

#[test]
fn an_empty_ca_file_is_an_error_naming_the_file() {
    let dir = temp_dir("tls-unit");
    std::fs::write(dir.join("empty-ca.pem"), "").unwrap();
    let err = try_build_verifier(&dir, r#"{ "mode": "required", "caPath": "empty-ca.pem" }"#)
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("empty-ca.pem"), "{err}");
}

#[test]
fn a_garbage_ca_file_is_an_error_naming_the_file() {
    let dir = temp_dir("tls-unit");
    std::fs::write(dir.join("junk-ca.pem"), "this is not a certificate at all").unwrap();
    let err = try_build_verifier(&dir, r#"{ "mode": "required", "caPath": "junk-ca.pem" }"#)
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("junk-ca.pem"), "{err}");
}

#[test]
fn a_pem_block_with_undecodable_certificate_bytes_is_rejected_when_added_as_a_trust_anchor() {
    let dir = temp_dir("tls-unit");
    // Valid PEM framing and base64, but the payload isn't an X.509 certificate.
    std::fs::write(dir.join("bad-ca.pem"), "-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----\n").unwrap();
    let err = try_build_verifier(&dir, r#"{ "mode": "required", "caPath": "bad-ca.pem" }"#)
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("bad-ca.pem"), "{err}");
}

#[test]
fn a_missing_crl_file_is_an_error_naming_the_file() {
    let dir = dir_with_ca(&Ca::root("ca"));
    let err = try_build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["gone.crl"] }"#)
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("gone.crl"), "{err}");
}

#[test]
fn an_unparseable_crl_file_is_an_error_naming_the_file() {
    let dir = dir_with_ca(&Ca::root("ca"));
    std::fs::write(dir.join("junk.crl"), b"\x00\x01\x02 not a crl").unwrap();
    let err = try_build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["junk.crl"] }"#)
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("junk.crl"), "{err}");

    std::fs::write(dir.join("pem-junk.crl"), "-----BEGIN X509 CRL-----\naGVsbG8gd29ybGQ=\n-----END X509 CRL-----\n").unwrap();
    let err = try_build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["pem-junk.crl"] }"#)
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("pem-junk.crl"), "{err}");
}

#[test]
fn a_pem_file_with_no_crl_block_is_an_error_naming_the_file() {
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    std::fs::write(dir.join("not-a-crl.pem"), ca.pem()).unwrap();
    let err = try_build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["not-a-crl.pem"] }"#)
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("not-a-crl.pem"), "{err}");
}

#[test]
fn crlf_converted_pem_files_load() {
    let ca = Ca::root("ca");
    let dir = temp_dir("tls-unit");
    std::fs::write(dir.join("client-ca.pem"), ca.pem().replace('\n', "\r\n")).unwrap();
    std::fs::write(dir.join("a.crl"), ca.fresh_crl_pem(&[]).replace('\n', "\r\n")).unwrap();
    let built = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["a.crl"] }"#);
    assert_eq!(built.next_updates.len(), 1);
}

#[test]
fn a_der_encoded_crl_loads() {
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    let der = CertificateRevocationListDer::from_pem_slice(ca.fresh_crl_pem(&[]).as_bytes()).unwrap();
    std::fs::write(dir.join("a.crl"), der.as_ref()).unwrap();
    let built = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["a.crl"] }"#);
    assert_eq!(built.next_updates.len(), 1);
}

#[test]
fn a_pem_file_holding_several_crls_registers_each_of_them() {
    let ca = Ca::root("ca");
    let other = Ca::root("other");
    let dir = dir_with_ca(&ca);
    std::fs::write(dir.join("both.crl"), format!("{}{}", ca.fresh_crl_pem(&[]), other.fresh_crl_pem(&[]))).unwrap();
    let built = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["both.crl"] }"#);
    assert_eq!(built.next_updates.len(), 2);
}

#[test]
fn a_ca_bundle_with_two_certificates_trusts_clients_of_both() {
    let (a, b) = (Ca::root("a"), Ca::root("b"));
    let dir = temp_dir("tls-unit");
    std::fs::write(dir.join("client-ca.pem"), format!("{}{}", a.pem(), b.pem())).unwrap();
    let built = build_verifier(&dir, REQUIRED);
    assert!(verify(&built.verifier, &build_leaf(&a, &LeafSpec::valid()), &[]).is_ok());
    assert!(verify(&built.verifier, &build_leaf(&b, &LeafSpec::valid()), &[]).is_ok());
}

#[test]
fn crl_next_updates_are_reported_per_file() {
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    let next = now_unix() + 12 * DAY;
    std::fs::write(dir.join("a.crl"), ca.crl_pem(&[], now_unix() - DAY, next)).unwrap();
    let built = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["a.crl"] }"#);
    assert_eq!(built.next_updates.len(), 1);
    assert!(built.next_updates[0].0.ends_with("a.crl"));
    assert!((built.next_updates[0].1.timestamp() - next).abs() <= 1);
}

#[test]
fn no_crl_paths_warns_that_revocation_is_not_checked() {
    let dir = dir_with_ca(&Ca::root("ca"));
    let built = build_verifier(&dir, REQUIRED);
    assert!(built.warnings.iter().any(|w| w.contains("revocation is NOT checked")), "{:?}", built.warnings);
}

#[test]
fn configured_crls_suppress_the_no_revocation_warning() {
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    std::fs::write(dir.join("a.crl"), ca.fresh_crl_pem(&[])).unwrap();
    let built = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["a.crl"] }"#);
    assert!(built.warnings.is_empty(), "{:?}", built.warnings);
}

#[test]
fn disabling_the_eku_requirement_warns() {
    let dir = dir_with_ca(&Ca::root("ca"));
    let built = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "requireClientAuthEku": false }"#);
    assert!(built.warnings.iter().any(|w| w.contains("requireClientAuthEku")), "{:?}", built.warnings);
    let default = build_verifier(&dir, REQUIRED);
    assert!(!default.warnings.iter().any(|w| w.contains("requireClientAuthEku")));
}

// ----- build_server_config -----

fn config_dir(pki: &Pki) -> PathBuf {
    let dir = temp_dir("tls-cfg");
    write_basic_tls_files(&dir, pki);
    dir
}

#[test]
fn build_server_config_without_client_auth_keeps_rustls_resumption_defaults() {
    ensure_crypto_provider();
    let pki = Pki::new();
    let dir = config_dir(&pki);
    let built = build_server_config(&tls_config(None), &dir).unwrap();
    let defaults = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(pki.server_leaf.der())],
            PrivateKeyDer::from_pem_slice(pki.server_leaf.key_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    assert_eq!(built.config.send_tls13_tickets, defaults.send_tls13_tickets);
    assert_eq!(built.config.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(built.warnings.is_empty());
}

#[test]
fn build_server_config_with_a_bare_off_block_is_the_same_as_no_block() {
    ensure_crypto_provider();
    let pki = Pki::new();
    let dir = config_dir(&pki);
    let built = build_server_config(&tls_config(Some(r#"{ "mode": "off" }"#)), &dir).unwrap();
    assert!(built.warnings.is_empty());
    assert!(built.config.send_tls13_tickets > 0, "resumption stays on when client auth is off");
}

#[test]
fn build_server_config_disables_resumption_when_client_auth_is_on() {
    ensure_crypto_provider();
    let pki = Pki::new();
    let dir = config_dir(&pki);
    for mode in ["optional", "required"] {
        let built = build_server_config(&tls_config(Some(&format!(r#"{{ "mode": "{mode}", "caPath": "client-ca.pem" }}"#))), &dir).unwrap();
        assert_eq!(built.config.send_tls13_tickets, 0, "{mode}: no TLS1.3 tickets");
        assert!(!built.config.session_storage.can_cache(), "{mode}: no server-side session cache");
        assert!(!built.config.ticketer.enabled(), "{mode}: no stateless ticketer");
        assert_eq!(built.config.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }
}

#[test]
fn build_server_config_rejects_stray_fields_under_mode_off_before_reading_any_file() {
    ensure_crypto_provider();
    let dir = temp_dir("tls-cfg"); // deliberately empty: no cert files at all
    for (field, json) in [
        ("caPath", r#"{ "mode": "off", "caPath": "x.pem" }"#),
        ("crlPaths", r#"{ "mode": "off", "crlPaths": ["x.crl"] }"#),
        ("crlPolicy", r#"{ "mode": "off", "crlPolicy": "bestEffort" }"#),
        ("requireClientAuthEku", r#"{ "mode": "off", "requireClientAuthEku": false }"#),
    ] {
        let err = build_server_config(&tls_config(Some(json)), &dir).err().expect("must fail");
        assert!(err.to_string().contains(field), "{err}");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

#[test]
fn build_server_config_rejects_a_crl_policy_without_crl_paths_and_client_auth_without_a_ca() {
    ensure_crypto_provider();
    let dir = config_dir(&Pki::new());
    let err = build_server_config(
        &tls_config(Some(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPolicy": "failClosed" }"#)),
        &dir,
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("crlPolicy"), "{err}");
    let err = build_server_config(&tls_config(Some(r#"{ "mode": "required" }"#)), &dir).err().unwrap();
    assert!(err.to_string().contains("caPath"), "{err}");
}

#[test]
fn build_server_config_rejects_client_auth_over_plain_http() {
    let tls: crate::config::TlsConfig = serde_json::from_str(r#"{ "mode": "off", "clientAuth": { "mode": "required", "caPath": "ca.pem" } }"#).unwrap();
    let err = build_server_config(&tls, &temp_dir("tls-cfg")).err().unwrap();
    assert!(err.to_string().contains("manual"), "{err}");
}

#[test]
fn build_server_config_errors_name_both_the_cert_and_key_paths() {
    ensure_crypto_provider();
    let err = build_server_config(&tls_config(None), &temp_dir("tls-cfg")).err().unwrap();
    let text = err.to_string();
    assert!(text.contains("cert.pem") && text.contains("key.pem"), "{text}");
}

#[test]
fn build_server_config_errors_name_the_ca_file() {
    ensure_crypto_provider();
    let dir = config_dir(&Pki::new());
    let err = build_server_config(&tls_config(Some(r#"{ "mode": "required", "caPath": "missing-ca.pem" }"#)), &dir)
        .err()
        .unwrap();
    assert!(err.to_string().contains("missing-ca.pem"), "{err}");
}

// ---------------------------------------------------------------------
// the verifier wrapper (no sockets)
// ---------------------------------------------------------------------

#[test]
fn a_valid_client_certificate_is_accepted() {
    let ca = Ca::root("ca");
    let built = build_verifier(&dir_with_ca(&ca), REQUIRED);
    assert!(verify(&built.verifier, &build_leaf(&ca, &LeafSpec::valid()), &[]).is_ok());
}

#[test]
fn a_certificate_from_an_unrelated_ca_is_rejected_as_unknown_issuer() {
    let (ca, other) = (Ca::root("ca"), Ca::root("other"));
    let built = build_verifier(&dir_with_ca(&ca), REQUIRED);
    let result = verify(&built.verifier, &build_leaf(&other, &LeafSpec::valid()), &[]);
    assert!(is_cert_error(&result, |e| matches!(e, CertificateError::UnknownIssuer)), "{result:?}");
}

#[test]
fn expired_and_not_yet_valid_certificates_are_rejected() {
    let ca = Ca::root("ca");
    let built = build_verifier(&dir_with_ca(&ca), REQUIRED);
    let expired = verify(&built.verifier, &build_leaf(&ca, &LeafSpec::expired()), &[]);
    assert!(
        is_cert_error(&expired, |e| matches!(e, CertificateError::Expired | CertificateError::ExpiredContext { .. })),
        "{expired:?}"
    );
    let early = verify(&built.verifier, &build_leaf(&ca, &LeafSpec::not_yet_valid()), &[]);
    assert!(
        is_cert_error(&early, |e| matches!(e, CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. })),
        "{early:?}"
    );
}

#[test]
fn a_server_auth_only_certificate_is_rejected_by_default_and_even_with_the_eku_requirement_off() {
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    let strict = build_verifier(&dir, REQUIRED);
    let lenient = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "requireClientAuthEku": false }"#);
    let leaf = build_leaf(&ca, &LeafSpec::server_auth_only());
    assert!(is_cert_error(&verify(&strict.verifier, &leaf, &[]), |e| matches!(
        e,
        CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. }
    )));
    assert!(
        verify(&lenient.verifier, &leaf, &[]).is_err(),
        "an EKU that is present but lacks clientAuth stays rejected (webpki rule)"
    );
}

#[test]
fn a_certificate_with_no_eku_is_rejected_by_default_and_accepted_when_the_requirement_is_off() {
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    let strict = build_verifier(&dir, REQUIRED);
    let lenient = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "requireClientAuthEku": false }"#);
    let leaf = build_leaf(&ca, &LeafSpec::no_eku());
    assert!(is_cert_error(&verify(&strict.verifier, &leaf, &[]), |e| matches!(
        e,
        CertificateError::InvalidPurpose
    )));
    assert!(verify(&lenient.verifier, &leaf, &[]).is_ok());
    // Explicit true behaves like the default.
    let explicit = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "requireClientAuthEku": true }"#);
    assert!(verify(&explicit.verifier, &leaf, &[]).is_err());
}

#[test]
fn identity_extraction_failures_become_handshake_rejections() {
    let ca = Ca::root("ca");
    let built = build_verifier(&dir_with_ca(&ca), REQUIRED);
    for spec in [
        LeafSpec {
            cn: vec!["x\u{1}y".into()],
            ..LeafSpec::valid()
        },
        LeafSpec::with_dns_count(65),
        LeafSpec {
            dns: vec!["a".repeat(2048)],
            ..LeafSpec::valid()
        },
    ] {
        let result = verify(&built.verifier, &build_leaf(&ca, &spec), &[]);
        assert!(is_cert_error(&result, |e| matches!(e, CertificateError::Other(_))), "{result:?}");
    }
}

#[test]
fn the_inner_chain_check_runs_before_the_eku_and_identity_checks() {
    let (ca, other) = (Ca::root("ca"), Ca::root("other"));
    let built = build_verifier(&dir_with_ca(&ca), REQUIRED);
    // Wrong issuer AND no EKU AND a control-char CN: the reported failure must
    // be the chain one — the wrapper never gets a say about an unverified leaf.
    let leaf = build_leaf(
        &other,
        &LeafSpec {
            eku: Vec::new(),
            cn: vec!["x\u{1}".into()],
            ..LeafSpec::valid()
        },
    );
    let result = verify(&built.verifier, &leaf, &[]);
    assert!(is_cert_error(&result, |e| matches!(e, CertificateError::UnknownIssuer)), "{result:?}");
}

#[test]
fn the_wrapper_forwards_mandatory_and_offer_flags_for_each_mode() {
    let dir = dir_with_ca(&Ca::root("ca"));
    let required = build_verifier(&dir, REQUIRED).verifier;
    assert!(required.offer_client_auth());
    assert!(required.client_auth_mandatory(), "required must stay mandatory");
    let optional = build_verifier(&dir, OPTIONAL).verifier;
    assert!(optional.offer_client_auth());
    assert!(!optional.client_auth_mandatory(), "optional must never become mandatory");
    for v in [&required, &optional] {
        assert_eq!(v.root_hint_subjects().len(), 1);
        assert!(!v.supported_verify_schemes().is_empty());
        assert!(!v.requires_raw_public_keys());
    }
}

#[test]
fn a_revoked_certificate_is_rejected_under_both_policies() {
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    let leaf = build_leaf(&ca, &LeafSpec::valid());
    let other = build_leaf(&ca, &LeafSpec::valid());
    std::fs::write(dir.join("a.crl"), ca.fresh_crl_pem(std::slice::from_ref(&leaf.serial))).unwrap();
    for policy in ["failClosed", "bestEffort"] {
        let built = build_verifier(
            &dir,
            &format!(r#"{{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["a.crl"], "crlPolicy": "{policy}" }}"#),
        );
        let result = verify(&built.verifier, &leaf, &[]);
        assert!(is_cert_error(&result, |e| matches!(e, CertificateError::Revoked)), "{policy}: {result:?}");
        assert!(verify(&built.verifier, &other, &[]).is_ok(), "{policy}: an unlisted serial is fine");
    }
}

#[test]
fn an_issuer_with_no_loaded_crl_is_rejected_under_fail_closed_and_accepted_under_best_effort() {
    let (ca, unrelated) = (Ca::root("ca"), Ca::root("unrelated"));
    let dir = dir_with_ca(&ca);
    // A CRL is loaded, but for a different issuer than the one that signed the leaf.
    std::fs::write(dir.join("unrelated.crl"), unrelated.fresh_crl_pem(&[])).unwrap();
    let leaf = build_leaf(&ca, &LeafSpec::valid());

    let strict = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["unrelated.crl"] }"#);
    let result = verify(&strict.verifier, &leaf, &[]);
    assert!(is_cert_error(&result, |e| matches!(e, CertificateError::UnknownRevocationStatus)), "{result:?}");

    let lenient = build_verifier(
        &dir,
        r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["unrelated.crl"], "crlPolicy": "bestEffort" }"#,
    );
    assert!(verify(&lenient.verifier, &leaf, &[]).is_ok());
}

#[test]
fn an_expired_crl_is_rejected_under_fail_closed_and_accepted_under_best_effort() {
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    std::fs::write(dir.join("old.crl"), ca.crl_pem(&[], now_unix() - 10 * DAY, now_unix() - DAY)).unwrap();
    let leaf = build_leaf(&ca, &LeafSpec::valid());

    let strict = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["old.crl"] }"#);
    let result = verify(&strict.verifier, &leaf, &[]);
    assert!(
        is_cert_error(&result, |e| matches!(
            e,
            CertificateError::ExpiredRevocationList | CertificateError::ExpiredRevocationListContext { .. }
        )),
        "{result:?}"
    );

    let lenient = build_verifier(
        &dir,
        r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["old.crl"], "crlPolicy": "bestEffort" }"#,
    );
    assert!(verify(&lenient.verifier, &leaf, &[]).is_ok());
}

#[test]
fn an_expired_crl_that_lists_the_certificate_still_revokes_it_under_best_effort_only_if_enforced() {
    // Pins the documented semantics: bestEffort does not enforce CRL expiry,
    // and a CRL that webpki is willing to use still rejects what it lists.
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    let leaf = build_leaf(&ca, &LeafSpec::valid());
    std::fs::write(
        dir.join("old.crl"),
        ca.crl_pem(std::slice::from_ref(&leaf.serial), now_unix() - 10 * DAY, now_unix() - DAY),
    )
    .unwrap();
    let lenient = build_verifier(
        &dir,
        r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["old.crl"], "crlPolicy": "bestEffort" }"#,
    );
    let result = verify(&lenient.verifier, &leaf, &[]);
    assert!(is_cert_error(&result, |e| matches!(e, CertificateError::Revoked)), "{result:?}");
}

#[test]
fn a_root_intermediate_leaf_chain_is_accepted_without_crls() {
    let root = Ca::root("root");
    let inter = root.intermediate("intermediate");
    let built = build_verifier(&dir_with_ca(&root), REQUIRED);
    let leaf = build_leaf(&inter, &LeafSpec::valid());
    assert!(verify(&built.verifier, &leaf, &[&inter]).is_ok());
    // Without the intermediate presented the chain can't be built.
    assert!(verify(&built.verifier, &leaf, &[]).is_err());
}

#[test]
fn a_chain_is_accepted_with_crls_from_both_issuers_and_checks_the_whole_chain() {
    let root = Ca::root("root");
    let inter = root.intermediate("intermediate");
    let dir = dir_with_ca(&root);
    let leaf = build_leaf(&inter, &LeafSpec::valid());
    std::fs::write(dir.join("root.crl"), root.fresh_crl_pem(&[])).unwrap();
    std::fs::write(dir.join("inter.crl"), inter.fresh_crl_pem(&[])).unwrap();
    let both = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["root.crl", "inter.crl"] }"#);
    assert!(verify(&both.verifier, &leaf, &[&inter]).is_ok());

    // Only the intermediate's CRL: the intermediate certificate's own status
    // (which only the root's CRL could give) is unknown -> fail closed.
    let only_inter = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["inter.crl"] }"#);
    assert!(verify(&only_inter.verifier, &leaf, &[&inter]).is_err());
}

#[test]
fn a_revoked_intermediate_rejects_every_leaf_under_it() {
    let root = Ca::root("root");
    let inter = root.intermediate("intermediate");
    let dir = dir_with_ca(&root);
    let inter_serial = {
        let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(inter.cert.der()).unwrap();
        parsed.raw_serial().to_vec()
    };
    std::fs::write(dir.join("root.crl"), root.fresh_crl_pem(&[inter_serial])).unwrap();
    std::fs::write(dir.join("inter.crl"), inter.fresh_crl_pem(&[])).unwrap();
    let built = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["root.crl", "inter.crl"] }"#);
    let result = verify(&built.verifier, &build_leaf(&inter, &LeafSpec::valid()), &[&inter]);
    assert!(is_cert_error(&result, |e| matches!(e, CertificateError::Revoked)), "{result:?}");
}

// ---------------------------------------------------------------------
// CRL freshness helpers
// ---------------------------------------------------------------------

fn ts(unix: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(unix, 0).unwrap()
}

#[test]
fn crl_freshness_classifies_expired_soon_and_fine_with_inclusive_boundaries() {
    let now = ts(1_800_000_000);
    let week = CRL_EXPIRY_WARNING_DAYS * DAY;
    let updates = vec![
        (PathBuf::from("expired.crl"), now - chrono::Duration::seconds(1)),
        (PathBuf::from("exactly-now.crl"), now),
        (PathBuf::from("soon.crl"), now + chrono::Duration::seconds(1)),
        (PathBuf::from("exactly-seven-days.crl"), ts(1_800_000_000 + week)),
        (PathBuf::from("just-past-seven-days.crl"), ts(1_800_000_000 + week + 1)),
        (PathBuf::from("far.crl"), now + chrono::Duration::days(90)),
    ];
    let findings: Vec<(String, CrlStatus)> = crl_freshness(&updates, now).into_iter().map(|(p, _, s)| (p.display().to_string(), s)).collect();
    assert_eq!(
        findings,
        vec![
            ("expired.crl".to_string(), CrlStatus::Expired),
            ("exactly-now.crl".to_string(), CrlStatus::Expired),
            ("soon.crl".to_string(), CrlStatus::ExpiringSoon),
            ("exactly-seven-days.crl".to_string(), CrlStatus::ExpiringSoon),
        ]
    );
    assert_eq!(CRL_EXPIRY_WARNING_DAYS, 7);
}

#[test]
fn crl_freshness_of_nothing_is_nothing() {
    assert!(crl_freshness(&[], Utc::now()).is_empty());
}

#[test]
fn a_crl_whose_next_update_is_three_days_away_is_reported_as_expiring_soon_from_a_real_file() {
    let ca = Ca::root("ca");
    let dir = dir_with_ca(&ca);
    std::fs::write(dir.join("a.crl"), ca.crl_pem(&[], now_unix() - DAY, now_unix() + 3 * DAY)).unwrap();
    let built = build_verifier(&dir, r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["a.crl"] }"#);
    let findings = crl_freshness(&built.next_updates, Utc::now());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].2, CrlStatus::ExpiringSoon);
}

#[tokio::test]
async fn startup_freshness_warnings_distinguish_expired_fail_closed_from_the_rest() {
    let logs = LogBuffer::default();
    let _guard = logs.install(tracing::Level::DEBUG);
    let updates = vec![
        (PathBuf::from("old.crl"), Utc::now() - chrono::Duration::days(1)),
        (PathBuf::from("soon.crl"), Utc::now() + chrono::Duration::days(2)),
        (PathBuf::from("fine.crl"), Utc::now() + chrono::Duration::days(60)),
    ];
    warn_about_crl_freshness(&updates, true);
    let text = logs.text();
    assert!(text.contains("ERROR") && text.contains("old.crl") && text.contains("failClosed"), "{text}");
    assert!(text.contains("soon.crl") && text.contains("WARN"), "{text}");
    assert!(!text.contains("fine.crl"), "{text}");

    let logs = LogBuffer::default();
    let _guard2 = logs.install(tracing::Level::DEBUG);
    warn_about_crl_freshness(&updates[..1], false);
    assert!(logs.text().contains("WARN") && !logs.text().contains("ERROR"), "{}", logs.text());
}

#[tokio::test]
async fn the_expiry_watch_has_nothing_to_wait_for_without_a_future_next_update() {
    assert!(spawn_crl_expiry_watch(&[]).is_none());
    assert!(spawn_crl_expiry_watch(&[(PathBuf::from("old.crl"), Utc::now() - chrono::Duration::days(1))]).is_none());
}

#[tokio::test]
async fn the_expiry_watch_logs_once_the_earliest_next_update_passes() {
    let logs = LogBuffer::default();
    let _guard = logs.install(tracing::Level::DEBUG);
    let handle = spawn_crl_expiry_watch(&[
        (PathBuf::from("late.crl"), Utc::now() + chrono::Duration::days(3)),
        (PathBuf::from("early.crl"), Utc::now() + chrono::Duration::milliseconds(300)),
    ])
    .expect("a future nextUpdate means there is something to wait for");
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the watch should finish at the earliest nextUpdate")
        .unwrap();
    let text = logs.text();
    assert!(text.contains("early.crl") && text.contains("expired"), "{text}");
    assert!(!text.contains("late.crl"), "{text}");
}

// ---------------------------------------------------------------------
// IdentityService
// ---------------------------------------------------------------------

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Option<String>>>>);

impl tower_service::Service<Request<()>> for Recorder {
    type Response = ();
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<(), Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<()>) -> Self::Future {
        let seen = request.extensions().get::<Arc<ClientCertIdentity>>().map(|id| id.fingerprint().to_string());
        self.0.lock().unwrap().push(seen);
        std::future::ready(Ok(()))
    }
}

fn identity(ca: &Ca) -> Arc<ClientCertIdentity> {
    Arc::new(ClientCertIdentity::from_der(&build_leaf(ca, &LeafSpec::valid()).der()).unwrap())
}

#[tokio::test]
async fn a_preexisting_identity_extension_is_removed_when_the_connection_has_none() {
    let ca = Ca::root("ca");
    let spoofed = identity(&ca);
    let recorder = Recorder::default();
    let mut service = IdentityService {
        inner: recorder.clone(),
        identity: None,
    };
    let mut request = Request::new(());
    request.extensions_mut().insert(spoofed);
    service.call(request).await.unwrap();
    assert_eq!(recorder.0.lock().unwrap().as_slice(), &[None]);
}

#[tokio::test]
async fn a_preexisting_identity_extension_is_replaced_by_the_connections_own() {
    let ca = Ca::root("ca");
    let (spoofed, real) = (identity(&ca), identity(&ca));
    assert_ne!(spoofed.fingerprint(), real.fingerprint());
    let recorder = Recorder::default();
    let mut service = IdentityService {
        inner: recorder.clone(),
        identity: Some(real.clone()),
    };
    let mut request = Request::new(());
    request.extensions_mut().insert(spoofed);
    service.call(request).await.unwrap();
    assert_eq!(recorder.0.lock().unwrap().as_slice(), &[Some(real.fingerprint().to_string())]);
}

#[tokio::test]
async fn every_request_on_a_connection_carries_that_connections_identity() {
    let ca = Ca::root("ca");
    let real = identity(&ca);
    let recorder = Recorder::default();
    let mut service = IdentityService {
        inner: recorder.clone(),
        identity: Some(real.clone()),
    };
    for _ in 0..3 {
        service.call(Request::new(())).await.unwrap();
    }
    let seen = recorder.0.lock().unwrap().clone();
    assert_eq!(seen, vec![Some(real.fingerprint().to_string()); 3]);
}

use tower_service::Service;
