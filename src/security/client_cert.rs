use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

use super::valid_if::ValidIf;
use crate::sql::SqlValue;

/// A leaf certificate larger than this is rejected during the handshake
/// rather than parsed — a legitimate client cert is a couple of KiB.
const MAX_LEAF_DER_BYTES: usize = 16 * 1024;
const MAX_SAN_ENTRIES: usize = 64;
const MAX_IDENTITY_VALUE_BYTES: usize = 1024;
const MAX_DN_BYTES: usize = 4096;

/// Why `ClientCertIdentity::from_der` refused a certificate. The message is
/// a fixed, value-free string: it ends up in debug logs only, and never
/// echoes anything attacker-controlled (a CN or DN) back out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityError(pub(crate) &'static str);

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for IdentityError {}

/// The already-chain-validated identity of the client certificate a
/// connection presented — parsed once, right after the TLS handshake, and
/// attached to every request on that connection as a request extension by
/// `server::tls::ClientCertAcceptor`. Holds only derived text fields, never
/// the raw chain. No header can ever populate one of these.
///
/// `Debug` is deliberately redacted: a CN/DN/SAN is caller-supplied text and
/// must not reach a log line by an accidental `{:?}`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ClientCertIdentity {
    cn: Option<String>,
    subject: String,
    issuer: String,
    serial: String,
    fingerprint: String,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    san_dns: Vec<String>,
    san_uri: Vec<String>,
    san_email: Vec<String>,
}

impl fmt::Debug for ClientCertIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientCertIdentity { .. }")
    }
}

/// The caller-supplied pieces of an identity for `frogs test` (a case's
/// `clientCert`) — there's no real certificate behind it. Every field is
/// optional; an absent `not_after` counts as "never expires".
#[derive(Debug, Clone, Default)]
pub(crate) struct TestIdentityFields {
    pub cn: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub fingerprint: Option<String>,
    pub not_after: Option<DateTime<Utc>>,
    pub san_dns: Vec<String>,
    pub san_uri: Vec<String>,
    pub san_email: Vec<String>,
}

/// A scalar or SAN field a verifier can read off the identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertField {
    Cn,
    Subject,
    Issuer,
    Serial,
    Fingerprint,
    NotAfter,
    SanDns,
    SanUri,
    SanEmail,
}

impl CertField {
    /// Parses the part after `cert.` — `cn`, `subject`, `issuer`, `serial`,
    /// `fingerprint`, `notAfter`, `san.dns`, `san.uri`, `san.email`.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "cn" => CertField::Cn,
            "subject" => CertField::Subject,
            "issuer" => CertField::Issuer,
            "serial" => CertField::Serial,
            "fingerprint" => CertField::Fingerprint,
            "notAfter" => CertField::NotAfter,
            "san.dns" => CertField::SanDns,
            "san.uri" => CertField::SanUri,
            "san.email" => CertField::SanEmail,
            _ => return None,
        })
    }

    /// `false` for the multi-valued SAN fields: a SQL/HTTP parameter binds
    /// one scalar, and "first SAN wins" would silently authorize on an
    /// arbitrary entry, so those are expressible only via the `mtls`
    /// verifier's any-of matching.
    pub(crate) fn is_bindable(self) -> bool {
        !matches!(self, CertField::SanDns | CertField::SanUri | CertField::SanEmail)
    }
}

impl ClientCertIdentity {
    /// Parses a presented leaf certificate. Every `Err` here is a handshake
    /// rejection, not a request-time error — see `server::tls`.
    pub(crate) fn from_der(der: &[u8]) -> Result<Self, IdentityError> {
        if der.len() > MAX_LEAF_DER_BYTES {
            return Err(IdentityError("client certificate is too large"));
        }
        let (_, cert) = X509Certificate::from_der(der).map_err(|_| IdentityError("client certificate could not be parsed"))?;

        let subject = render_dn(cert.subject())?;
        let issuer = render_dn(cert.issuer())?;

        let mut cn_values = Vec::new();
        for attr in cert.subject().iter_common_name() {
            if let Ok(value) = attr.as_str() {
                check_text(value, MAX_IDENTITY_VALUE_BYTES)?;
                cn_values.push(value.to_string());
            } else {
                cn_values.push(String::new());
            }
        }
        let cn = if cn_values.len() == 1 && !cn_values[0].is_empty() { cn_values.pop() } else { None };

        let mut san_dns = Vec::new();
        let mut san_uri = Vec::new();
        let mut san_email = Vec::new();
        if let Some(san) = cert
            .subject_alternative_name()
            .map_err(|_| IdentityError("client certificate has an invalid subjectAltName extension"))?
        {
            if san.value.general_names.len() > MAX_SAN_ENTRIES {
                return Err(IdentityError("client certificate has too many subjectAltName entries"));
            }
            for name in &san.value.general_names {
                match name {
                    GeneralName::DNSName(value) => san_dns.push(check_san(value)?),
                    GeneralName::URI(value) => san_uri.push(check_san(value)?),
                    GeneralName::RFC822Name(value) => san_email.push(check_san(value)?),
                    GeneralName::Invalid(..) => return Err(IdentityError("client certificate has an undecodable subjectAltName entry")),
                    _ => {}
                }
            }
        }

        let validity = cert.validity();
        Ok(ClientCertIdentity {
            cn,
            subject,
            issuer,
            serial: serial_hex(cert.raw_serial()),
            fingerprint: hex(ring::digest::digest(&ring::digest::SHA256, der).as_ref()),
            not_before: DateTime::from_timestamp(validity.not_before.timestamp(), 0),
            not_after: DateTime::from_timestamp(validity.not_after.timestamp(), 0),
            san_dns,
            san_uri,
            san_email,
        })
    }

    /// `frogs test` only — builds an identity from a case's `clientCert`
    /// block. Nothing outside `crate::testing` (and this module's own tests)
    /// has any reason to call this.
    pub(crate) fn from_test_fields(fields: TestIdentityFields) -> Self {
        ClientCertIdentity {
            cn: fields.cn,
            subject: fields.subject.unwrap_or_default(),
            issuer: fields.issuer.unwrap_or_default(),
            serial: fields.serial.map(|s| normalize_hex(&s).unwrap_or(s)).unwrap_or_default(),
            fingerprint: fields.fingerprint.map(|s| normalize_hex(&s).unwrap_or(s)).unwrap_or_default(),
            not_before: None,
            not_after: fields.not_after,
            san_dns: fields.san_dns,
            san_uri: fields.san_uri,
            san_email: fields.san_email,
        }
    }

    /// Reads an identity back out of the JSON shape `to_json` produces — how
    /// a mocked `verifier` success value for an `mtls` scheme is evaluated
    /// by the same `MtlsCondition` a real certificate goes through. `None`
    /// when the value isn't an object or a field has the wrong shape.
    pub(crate) fn from_identity_json(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let text = |key: &str| -> Option<Option<String>> {
            match object.get(key) {
                None | Some(Value::Null) => Some(None),
                Some(Value::String(s)) => Some(Some(s.clone())),
                Some(_) => None,
            }
        };
        let not_after = match text("notAfter")? {
            Some(raw) => Some(DateTime::parse_from_rfc3339(&raw).ok()?.with_timezone(&Utc)),
            None => None,
        };
        let (mut san_dns, mut san_uri, mut san_email) = (Vec::new(), Vec::new(), Vec::new());
        match object.get("san") {
            None | Some(Value::Null) => {}
            Some(Value::Object(san)) => {
                for (key, target) in [("dns", &mut san_dns), ("uri", &mut san_uri), ("email", &mut san_email)] {
                    match san.get(key) {
                        None | Some(Value::Null) => {}
                        Some(Value::String(s)) => target.push(s.clone()),
                        Some(Value::Array(items)) => {
                            for item in items {
                                target.push(item.as_str()?.to_string());
                            }
                        }
                        Some(_) => return None,
                    }
                }
            }
            Some(_) => return None,
        }
        Some(Self::from_test_fields(TestIdentityFields {
            cn: text("cn")?,
            subject: text("subject")?,
            issuer: text("issuer")?,
            serial: text("serial")?,
            fingerprint: text("fingerprint")?,
            not_after,
            san_dns,
            san_uri,
            san_email,
        }))
    }

    /// The shape `from_identity_json` reads back; kept for tests and mock
    /// authoring rather than any production path.
    #[allow(dead_code)]
    pub(crate) fn to_json(&self) -> Value {
        let mut san = Map::new();
        san.insert("dns".into(), Value::from(self.san_dns.clone()));
        san.insert("uri".into(), Value::from(self.san_uri.clone()));
        san.insert("email".into(), Value::from(self.san_email.clone()));
        let mut object = Map::new();
        object.insert("cn".into(), self.cn.clone().map(Value::from).unwrap_or(Value::Null));
        object.insert("subject".into(), Value::from(self.subject.clone()));
        object.insert("issuer".into(), Value::from(self.issuer.clone()));
        object.insert("serial".into(), Value::from(self.serial.clone()));
        object.insert("fingerprint".into(), Value::from(self.fingerprint.clone()));
        object.insert("notAfter".into(), self.not_after.map(|t| Value::from(rfc3339(t))).unwrap_or(Value::Null));
        object.insert("san".into(), Value::Object(san));
        Value::Object(object)
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Defense in depth: the handshake already rejected an out-of-validity
    /// cert, but a long-lived keep-alive connection can outlive the cert it
    /// authenticated with. A missing bound (a `frogs test` identity with no
    /// `notAfter`) counts as unbounded on that side.
    pub(crate) fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        if let Some(not_before) = self.not_before
            && now < not_before
        {
            return false;
        }
        if let Some(not_after) = self.not_after
            && now >= not_after
        {
            return false;
        }
        true
    }

    /// The value a `cert.<field>` verifier parameter binds: text, or `Null`
    /// when the identity doesn't have that field. `None` for a field that
    /// isn't bindable (the SANs).
    pub(crate) fn bind_value(&self, field: CertField) -> Option<SqlValue> {
        let text = |s: &str| if s.is_empty() { SqlValue::Null } else { SqlValue::Text(s.to_string()) };
        Some(match field {
            CertField::Cn => self.cn.as_deref().map(|s| SqlValue::Text(s.to_string())).unwrap_or(SqlValue::Null),
            CertField::Subject => text(&self.subject),
            CertField::Issuer => text(&self.issuer),
            CertField::Serial => text(&self.serial),
            CertField::Fingerprint => text(&self.fingerprint),
            CertField::NotAfter => self.not_after.map(|t| SqlValue::Text(rfc3339(t))).unwrap_or(SqlValue::Null),
            CertField::SanDns | CertField::SanUri | CertField::SanEmail => return None,
        })
    }
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Lowercase hex magnitude, with the DER sign-padding `00` bytes removed
/// (but always at least one digit pair).
fn serial_hex(raw: &[u8]) -> String {
    let start = raw.iter().position(|b| *b != 0).unwrap_or(raw.len().saturating_sub(1));
    if raw.is_empty() { "00".to_string() } else { hex(&raw[start..]) }
}

/// Lowercases and strips `:` separators; `None` if what's left isn't a
/// non-empty run of hex digits.
fn normalize_hex(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| *c != ':').collect::<String>().to_ascii_lowercase();
    if cleaned.is_empty() || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        None
    } else {
        Some(cleaned)
    }
}

fn check_text(value: &str, max_bytes: usize) -> Result<(), IdentityError> {
    if value.len() > max_bytes {
        return Err(IdentityError("client certificate has an oversized name value"));
    }
    if value.chars().any(char::is_control) {
        return Err(IdentityError("client certificate has a control character in a name"));
    }
    Ok(())
}

fn check_san(value: &str) -> Result<String, IdentityError> {
    check_text(value, MAX_IDENTITY_VALUE_BYTES)?;
    if !value.is_ascii() || value.contains(' ') {
        return Err(IdentityError("client certificate has a non-ASCII or space-containing subjectAltName entry"));
    }
    Ok(value.to_string())
}

fn short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.6" => "C",
        "2.5.4.9" => "STREET",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        _ => return None,
    })
}

fn escape_rfc4514(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let last = value.chars().count().saturating_sub(1);
    for (i, c) in value.chars().enumerate() {
        let needs_escape = matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';') || (i == 0 && (c == '#' || c == ' ')) || (i == last && c == ' ');
        if needs_escape {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// RFC 4514 string form: RDNs most-specific first (reverse of DER order),
/// `,`-separated, multi-valued RDN attributes joined with `+`.
fn render_dn(name: &X509Name<'_>) -> Result<String, IdentityError> {
    let mut rdns = Vec::new();
    for rdn in name.iter_rdn() {
        let mut parts = Vec::new();
        for attr in rdn.iter() {
            let oid = attr.attr_type().to_id_string();
            let label = short_name(&oid).map(str::to_string).unwrap_or(oid);
            let value = match attr.as_str() {
                Ok(text) => {
                    check_text(text, MAX_DN_BYTES)?;
                    escape_rfc4514(text)
                }
                Err(_) => {
                    let any = attr.attr_value();
                    let mut der = Vec::with_capacity(any.data.len() + 6);
                    der.push(any.header.raw_tag().map(|t| t[0]).unwrap_or_else(|| any.tag().0 as u8));
                    push_der_length(&mut der, any.data.len());
                    der.extend_from_slice(any.data);
                    format!("#{}", hex(&der))
                }
            };
            parts.push(format!("{label}={value}"));
        }
        rdns.push(parts.join("+"));
    }
    rdns.reverse();
    let rendered = rdns.join(",");
    if rendered.len() > MAX_DN_BYTES {
        return Err(IdentityError("client certificate has an oversized distinguished name"));
    }
    Ok(rendered)
}

fn push_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// `None` when the leaf has no EKU extension at all, otherwise whether it
/// lists `clientAuth`. `Err` when the certificate or extension is
/// unparseable.
pub(crate) fn leaf_client_auth_eku(der: &[u8]) -> Result<Option<bool>, IdentityError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| IdentityError("client certificate could not be parsed"))?;
    let eku = cert
        .extended_key_usage()
        .map_err(|_| IdentityError("client certificate has an invalid extendedKeyUsage extension"))?;
    Ok(eku.map(|e| e.value.client_auth))
}

/// An `mtls` verifier's compiled `validIf` — `cert.<field> = <value>`, with
/// the value compared as raw text (never run through `ValidIf`'s literal
/// parsing, which would turn `0012` into the integer 12) and SAN fields
/// matched any-of across every entry of that kind (RFC 6125 / RFC 5280).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsCondition {
    field: CertField,
    expected: String,
}

impl MtlsCondition {
    pub(crate) fn compile(raw_valid_if: &str) -> Result<Self, String> {
        ValidIf::parse(raw_valid_if).map_err(|e| e.to_string())?;
        let (left, right) = raw_valid_if.split_once('=').ok_or_else(|| "validIf has no '='".to_string())?;
        let left = left.trim();
        let field_name = left
            .strip_prefix("cert.")
            .ok_or_else(|| format!("an mtls verifier's validIf must start with the label 'cert.', got '{left}'"))?;
        let field = CertField::parse(field_name).ok_or_else(|| {
            format!("unknown certificate field '{field_name}' — expected one of cn, subject, issuer, serial, fingerprint, notAfter, san.dns, san.uri, san.email")
        })?;

        let right = right.trim();
        let expected = right.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(right);
        if expected.is_empty() {
            return Err(format!("validIf compares cert.{field_name} against an empty value"));
        }

        let expected = match field {
            CertField::Serial | CertField::Fingerprint => normalize_hex(expected).ok_or_else(|| format!("cert.{field_name} must be compared against a hex string"))?,
            CertField::SanDns => {
                if !expected.is_ascii() {
                    return Err("cert.san.dns must be compared against an ASCII hostname (use the A-label form for internationalized names)".to_string());
                }
                let lowered = expected.to_ascii_lowercase();
                let trimmed = lowered.strip_suffix('.').unwrap_or(&lowered).to_string();
                if trimmed.is_empty() {
                    return Err("cert.san.dns is compared against an empty hostname".to_string());
                }
                trimmed
            }
            CertField::SanEmail => {
                let (local, domain) = expected
                    .rsplit_once('@')
                    .filter(|(l, d)| !l.is_empty() && !d.is_empty())
                    .ok_or_else(|| "cert.san.email must be compared against a 'local@domain' address".to_string())?;
                format!("{local}@{}", domain.to_ascii_lowercase())
            }
            _ => expected.to_string(),
        };
        Ok(MtlsCondition { field, expected })
    }

    pub(crate) fn matches(&self, identity: &ClientCertIdentity) -> bool {
        match self.field {
            CertField::Cn => identity.cn.as_deref() == Some(self.expected.as_str()),
            CertField::Subject => identity.subject == self.expected,
            CertField::Issuer => identity.issuer == self.expected,
            CertField::Serial => identity.serial == self.expected,
            CertField::Fingerprint => identity.fingerprint == self.expected,
            CertField::NotAfter => identity.not_after.map(rfc3339).as_deref() == Some(self.expected.as_str()),
            CertField::SanDns => identity
                .san_dns
                .iter()
                .any(|presented| presented.strip_suffix('.').unwrap_or(presented).eq_ignore_ascii_case(&self.expected)),
            CertField::SanUri => identity.san_uri.contains(&self.expected),
            CertField::SanEmail => {
                let Some((expected_local, expected_domain)) = self.expected.rsplit_once('@') else {
                    return false;
                };
                identity.san_email.iter().any(|presented| {
                    presented
                        .rsplit_once('@')
                        .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty() && local == expected_local && domain.eq_ignore_ascii_case(expected_domain))
                })
            }
        }
    }
}

#[cfg(test)]
mod tests;
