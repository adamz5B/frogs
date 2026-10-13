//! Test-only PKI: root/intermediate CAs, server and client leaves in every
//! shape the mTLS tests need, CRLs, and a raw-DER certificate builder for
//! shapes `rcgen` can't express (multi-valued RDNs, non-string DN values,
//! non-ASCII dNSName). Everything is generated in memory at test time — no
//! committed fixtures.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams, DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
    KeyPair, KeyUsagePurpose, RevokedCertParams, SanType, SerialNumber,
};

pub(crate) const DAY: i64 = 86_400;

pub(crate) fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn apply_validity(params: &mut CertificateParams, not_before: i64, not_after: i64) {
    let epoch = rcgen::date_time_ymd(1970, 1, 1);
    params.not_before = epoch + Duration::from_secs(not_before as u64);
    params.not_after = epoch + Duration::from_secs(not_after as u64);
}

/// A serial no other leaf in this test binary shares, with the high bit
/// clear so rcgen/webpki never need sign padding.
pub(crate) fn unique_serial() -> Vec<u8> {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
    let mut bytes = vec![0x01];
    bytes.extend_from_slice(&nanos.to_be_bytes());
    bytes.extend_from_slice(&n.to_be_bytes());
    bytes
}

pub(crate) struct Ca {
    pub cert: Certificate,
    pub key: KeyPair,
}

impl Ca {
    pub fn root(cn: &str) -> Ca {
        Self::build(cn, None)
    }

    pub fn intermediate(&self, cn: &str) -> Ca {
        Self::build(cn, Some(self))
    }

    fn build(cn: &str, issuer: Option<&Ca>) -> Ca {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        params.serial_number = Some(SerialNumber::from_slice(&unique_serial()));
        apply_validity(&mut params, now_unix() - DAY, now_unix() + 3650 * DAY);
        let key = KeyPair::generate().unwrap();
        let cert = match issuer {
            None => params.self_signed(&key).unwrap(),
            Some(issuer) => params.signed_by(&key, &issuer.cert, &issuer.key).unwrap(),
        };
        Ca { cert, key }
    }

    pub fn pem(&self) -> String {
        self.cert.pem()
    }

    /// A CRL signed by this CA revoking every listed serial (raw big-endian
    /// bytes), valid from `this_update` to `next_update` (unix seconds).
    pub fn crl_pem(&self, revoked_serials: &[Vec<u8>], this_update: i64, next_update: i64) -> String {
        let epoch = rcgen::date_time_ymd(1970, 1, 1);
        let params = CertificateRevocationListParams {
            this_update: epoch + Duration::from_secs(this_update as u64),
            next_update: epoch + Duration::from_secs(next_update as u64),
            crl_number: SerialNumber::from_slice(&[1]),
            issuing_distribution_point: None,
            revoked_certs: revoked_serials
                .iter()
                .map(|serial| RevokedCertParams {
                    serial_number: SerialNumber::from_slice(serial),
                    revocation_time: epoch + Duration::from_secs((this_update - 10) as u64),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        params.signed_by(&self.cert, &self.key).unwrap().pem().unwrap()
    }

    /// A currently fresh CRL (nextUpdate in 30 days).
    pub fn fresh_crl_pem(&self, revoked_serials: &[Vec<u8>]) -> String {
        self.crl_pem(revoked_serials, now_unix() - DAY, now_unix() + 30 * DAY)
    }
}

pub(crate) struct Leaf {
    pub cert: Certificate,
    pub key: KeyPair,
    pub serial: Vec<u8>,
}

impl Leaf {
    pub fn der(&self) -> Vec<u8> {
        self.cert.der().to_vec()
    }
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }
    /// Certificate then key in one PEM — what `reqwest::Identity::from_pem` takes.
    pub fn identity_pem(&self) -> String {
        format!("{}{}", self.cert_pem(), self.key_pem())
    }
    /// Leaf followed by the given intermediates (leaf first), then the key.
    pub fn identity_pem_with_chain(&self, intermediates: &[&Ca]) -> String {
        let mut pem = self.cert_pem();
        for ca in intermediates {
            pem.push_str(&ca.pem());
        }
        pem.push_str(&self.key_pem());
        pem
    }
}

#[derive(Clone)]
pub(crate) struct LeafSpec {
    /// CommonName attributes: the first uses the standard CN key, any extra
    /// ones are emitted as additional attributes with the same OID.
    pub cn: Vec<String>,
    pub extra_dn: Vec<(DnType, DnValue)>,
    pub dns: Vec<String>,
    pub uri: Vec<String>,
    pub email: Vec<String>,
    pub eku: Vec<ExtendedKeyUsagePurpose>,
    pub not_before: i64,
    pub not_after: i64,
    pub serial: Vec<u8>,
}

impl LeafSpec {
    /// The plan's "valid client leaf": ClientAuth EKU, single CN, three DNS
    /// SANs, two URI SANs, two emails.
    pub fn valid() -> Self {
        LeafSpec {
            cn: vec!["client.example.com".to_string()],
            extra_dn: Vec::new(),
            dns: vec!["a.svc.example".into(), "b.svc.example".into(), "orders.internal.example.com".into()],
            uri: vec!["spiffe://example.org/ns/a".into(), "spiffe://example.org/ns/orders".into()],
            email: vec!["first@example.com".into(), "Alice@Example.com".into()],
            eku: vec![ExtendedKeyUsagePurpose::ClientAuth],
            not_before: now_unix() - DAY,
            not_after: now_unix() + 30 * DAY,
            serial: unique_serial(),
        }
    }

    pub fn bare() -> Self {
        LeafSpec {
            dns: Vec::new(),
            uri: Vec::new(),
            email: Vec::new(),
            ..Self::valid()
        }
    }

    pub fn expired() -> Self {
        LeafSpec {
            not_before: now_unix() - 3 * DAY,
            not_after: now_unix() - DAY,
            ..Self::valid()
        }
    }

    pub fn not_yet_valid() -> Self {
        LeafSpec {
            not_before: now_unix() + DAY,
            not_after: now_unix() + 2 * DAY,
            ..Self::valid()
        }
    }

    pub fn server_auth_only() -> Self {
        LeafSpec {
            eku: vec![ExtendedKeyUsagePurpose::ServerAuth],
            ..Self::valid()
        }
    }

    pub fn no_eku() -> Self {
        LeafSpec {
            eku: Vec::new(),
            ..Self::valid()
        }
    }

    /// Valid now, expires `secs` from now.
    pub fn short_lived(secs: i64) -> Self {
        LeafSpec {
            not_after: now_unix() + secs,
            ..Self::valid()
        }
    }

    pub fn with_dns_count(n: usize) -> Self {
        LeafSpec {
            dns: (0..n).map(|i| format!("h{i}.example")).collect(),
            uri: Vec::new(),
            email: Vec::new(),
            ..Self::valid()
        }
    }
}

pub(crate) fn build_leaf(issuer: &Ca, spec: &LeafSpec) -> Leaf {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    for (i, cn) in spec.cn.iter().enumerate() {
        let value = DnValue::Utf8String(cn.clone());
        if i == 0 {
            dn.push(DnType::CommonName, value);
        } else {
            // Same OID (2.5.4.3) as CommonName, but a distinct map key in
            // rcgen — which is how a second CN attribute is expressed.
            dn.push(DnType::CustomDnType(vec![2, 5, 4, 3]), value);
        }
    }
    for (ty, value) in &spec.extra_dn {
        dn.push(ty.clone(), value.clone());
    }
    params.distinguished_name = dn;
    let mut sans = Vec::new();
    sans.extend(spec.dns.iter().map(|d| SanType::DnsName(d.as_str().try_into().unwrap())));
    sans.extend(spec.uri.iter().map(|u| SanType::URI(u.as_str().try_into().unwrap())));
    sans.extend(spec.email.iter().map(|e| SanType::Rfc822Name(e.as_str().try_into().unwrap())));
    params.subject_alt_names = sans;
    params.extended_key_usages = spec.eku.clone();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.serial_number = Some(SerialNumber::from_slice(&spec.serial));
    apply_validity(&mut params, spec.not_before, spec.not_after);
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    Leaf {
        cert,
        key,
        serial: spec.serial.clone(),
    }
}

/// A server certificate for `localhost` / 127.0.0.1.
pub(crate) fn build_server_leaf(issuer: &Ca) -> Leaf {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap()), SanType::IpAddress("127.0.0.1".parse().unwrap())];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let serial = unique_serial();
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    apply_validity(&mut params, now_unix() - DAY, now_unix() + 30 * DAY);
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    Leaf { cert, key, serial }
}

/// The two roots every handshake test needs: one that signs the server
/// certificate (the client trusts it) and one that signs client certificates
/// (the server trusts it), plus an unrelated third root.
pub(crate) struct Pki {
    pub server_ca: Ca,
    pub client_ca: Ca,
    pub wrong_ca: Ca,
    pub server_leaf: Leaf,
}

impl Pki {
    pub fn new() -> Pki {
        let server_ca = Ca::root("frogs test server root");
        let client_ca = Ca::root("frogs test client root");
        let wrong_ca = Ca::root("frogs test unrelated root");
        let server_leaf = build_server_leaf(&server_ca);
        Pki {
            server_ca,
            client_ca,
            wrong_ca,
            server_leaf,
        }
    }
}

// ---------------------------------------------------------------------
// Raw DER builder — for certificates rcgen can't express. The signature is
// garbage: `ClientCertIdentity::from_der` only parses, it never verifies.
// ---------------------------------------------------------------------

pub(crate) fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().position(|b| *b != 0).unwrap();
        let mut out = vec![0x80 | (bytes.len() - skip) as u8];
        out.extend_from_slice(&bytes[skip..]);
        out
    }
}

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn base128(mut n: u64) -> Vec<u8> {
    let mut out = vec![(n & 0x7f) as u8];
    n >>= 7;
    while n > 0 {
        out.push(0x80 | (n & 0x7f) as u8);
        n >>= 7;
    }
    out.reverse();
    out
}

pub(crate) fn oid_der(arcs: &[u64]) -> Vec<u8> {
    let mut content = base128(arcs[0] * 40 + arcs[1]);
    for arc in &arcs[2..] {
        content.extend(base128(*arc));
    }
    tlv(0x06, &content)
}

pub(crate) const OID_CN: &[u64] = &[2, 5, 4, 3];
pub(crate) const OID_O: &[u64] = &[2, 5, 4, 10];
pub(crate) const OID_OU: &[u64] = &[2, 5, 4, 11];

/// One AttributeTypeAndValue with an explicit string tag
/// (0x0c UTF8String, 0x13 PrintableString, 0x04 OCTET STRING, ...).
pub(crate) fn atv(oid: &[u64], tag: u8, value: &[u8]) -> Vec<u8> {
    let mut content = oid_der(oid);
    content.extend(tlv(tag, value));
    tlv(0x30, &content)
}

pub(crate) fn utf8_atv(oid: &[u64], value: &str) -> Vec<u8> {
    atv(oid, 0x0c, value.as_bytes())
}

/// An RDN (SET) of one or more attributes.
pub(crate) fn rdn(attrs: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &attrs.concat())
}

/// A Name (SEQUENCE of RDNs) in DER order.
pub(crate) fn name(rdns: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &rdns.concat())
}

/// A subjectAltName extension value built from `(context tag, bytes)`
/// entries, e.g. `(0x82, b"host")` for a dNSName.
pub(crate) fn raw_san_extension(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let content: Vec<u8> = entries.iter().flat_map(|(tag, bytes)| tlv(*tag, bytes)).collect();
    let general_names = tlv(0x30, &content);
    let mut ext = oid_der(&[2, 5, 29, 17]);
    ext.extend(tlv(0x04, &general_names));
    tlv(0x30, &ext)
}

/// A syntactically valid but unsigned (garbage-signature) X.509 v3
/// certificate. `serial` is the raw INTEGER content (include a leading 0x00
/// yourself if the top bit is set). `extensions` are complete Extension
/// SEQUENCEs.
pub(crate) fn raw_cert(subject: Vec<u8>, issuer: Vec<u8>, serial: &[u8], extensions: &[Vec<u8>], not_before: i64, not_after: i64) -> Vec<u8> {
    let key = KeyPair::generate().unwrap();
    let spki = key.public_key_der();
    let sig_alg = tlv(0x30, &oid_der(&[1, 2, 840, 10045, 4, 3, 2]));
    let utc = |unix: i64| {
        let t = chrono::DateTime::from_timestamp(unix, 0).unwrap();
        tlv(0x17, t.format("%y%m%d%H%M%SZ").to_string().as_bytes())
    };
    let validity = tlv(0x30, &[utc(not_before), utc(not_after)].concat());
    let mut tbs = tlv(0xa0, &tlv(0x02, &[2])); // version v3
    tbs.extend(tlv(0x02, serial));
    tbs.extend(sig_alg.clone());
    tbs.extend(issuer);
    tbs.extend(validity);
    tbs.extend(subject);
    tbs.extend(spki);
    if !extensions.is_empty() {
        tbs.extend(tlv(0xa3, &tlv(0x30, &extensions.concat())));
    }
    let tbs = tlv(0x30, &tbs);
    let mut cert = tbs;
    cert.extend(sig_alg);
    cert.extend(tlv(0x03, &[0x00, 0xde, 0xad, 0xbe, 0xef]));
    tlv(0x30, &cert)
}

/// A raw cert with the given subject and sensible defaults elsewhere.
pub(crate) fn raw_cert_with_subject(subject: Vec<u8>) -> Vec<u8> {
    let issuer = name(&[rdn(&[utf8_atv(OID_CN, "raw issuer")])]);
    raw_cert(subject, issuer, &[0x01], &[], now_unix() - DAY, now_unix() + DAY)
}

// ---------------------------------------------------------------------
// Shared test plumbing
// ---------------------------------------------------------------------

/// `main()`'s own `install_default()` never runs under `cargo test`; every
/// test that builds a rustls config or handshakes needs the same install.
pub(crate) fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A fresh, empty temp directory unique to this process/test.
pub(crate) fn temp_dir(tag: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-mtls-{tag}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Writes `cert.pem` / `key.pem` (the server leaf) and `client-ca.pem` (the
/// client CA) into `dir`.
pub(crate) fn write_basic_tls_files(dir: &std::path::Path, pki: &Pki) {
    std::fs::write(dir.join("cert.pem"), pki.server_leaf.cert_pem()).unwrap();
    std::fs::write(dir.join("key.pem"), pki.server_leaf.key_pem()).unwrap();
    std::fs::write(dir.join("client-ca.pem"), pki.client_ca.pem()).unwrap();
}

/// A `TlsConfig` for `manual` mode with the given `clientAuth` JSON object
/// (or none).
pub(crate) fn tls_config(client_auth_json: Option<&str>) -> crate::config::TlsConfig {
    let client_auth = client_auth_json.map(|c| format!(r#", "clientAuth": {c}"#)).unwrap_or_default();
    serde_json::from_str(&format!(
        r#"{{ "mode": "manual", "manual": {{ "certPath": "cert.pem", "keyPath": "key.pem" }}{client_auth} }}"#
    ))
    .unwrap()
}

/// Captures real tracing output so a test can assert on (or against) what a
/// code path logged. Install with `LogBuffer::install` on a current-thread
/// runtime (the `#[tokio::test]` default) so spawned tasks log into it too.
#[derive(Clone, Default)]
pub(crate) struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl LogBuffer {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).to_string()
    }

    pub fn install(&self, level: tracing::Level) -> tracing::dispatcher::DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(self.clone())
            .with_max_level(level)
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::dispatcher::set_default(&tracing::Dispatch::new(subscriber))
    }
}

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
