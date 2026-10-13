use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::http::Request;
use axum_server::accept::Accept;
use chrono::{DateTime, Utc};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, RootCertStore, ServerConfig, SignatureScheme};
use tokio_rustls::server::TlsStream;
use x509_parser::prelude::{CertificateRevocationList, FromDer};

use crate::config::{ClientAuthConfig, ClientAuthMode, CrlPolicy, ManualTlsConfig, TlsConfig};
use crate::security::ClientCertIdentity;
use crate::security::client_cert::leaf_client_auth_eku;

/// How long a client gets to finish the TLS handshake — also bounds how long
/// a connection that never presents (or finishes presenting) a certificate
/// can hold an accept slot. Matches axum-server's own non-test default;
/// stated explicitly so a dependency bump can't quietly change it.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A CRL whose `nextUpdate` is closer than this is warned about at startup
/// (and by `frogs validate`) before it lapses.
pub const CRL_EXPIRY_WARNING_DAYS: i64 = 7;

/// A fully built listener TLS configuration plus what a caller should tell
/// the operator about it.
pub struct BuiltTls {
    pub config: Arc<ServerConfig>,
    /// `nextUpdate` of every loaded CRL that declares one, by file.
    pub crl_next_updates: Vec<(PathBuf, DateTime<Utc>)>,
    pub warnings: Vec<String>,
}

fn pem_error(e: pem::Error) -> io::Error {
    match e {
        pem::Error::Io(io_error) => io_error,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

/// Builds the rustls `ServerConfig` for a `tls.mode: manual` listener —
/// server cert/key, plus (when `tls.clientAuth` is on) the client-cert
/// verifier. Does all file I/O and validation up front so `serve` can fail
/// before binding a port or writing the pidfile, and `frogs validate` can
/// dry-run exactly the same code.
pub fn build_server_config(tls: &TlsConfig, tls_base: &Path) -> io::Result<BuiltTls> {
    tls.validate_structure().map_err(|m| io::Error::new(io::ErrorKind::InvalidInput, m))?;
    let manual: &ManualTlsConfig = tls
        .manual
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tls.mode is \"manual\" but tls.manual (certPath/keyPath) is missing"))?;

    let cert_path = tls_base.join(&manual.cert_path);
    let key_path = tls_base.join(&manual.key_path);
    let load_error = |e: io::Error| {
        io::Error::new(
            e.kind(),
            format!("failed to load TLS cert/key ({}, {}): {e}", cert_path.display(), key_path.display()),
        )
    };
    let certs = CertificateDer::pem_file_iter(&cert_path)
        .map_err(pem_error)
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>().map_err(pem_error))
        .map_err(load_error)?;
    if certs.is_empty() {
        return Err(load_error(io::Error::new(io::ErrorKind::InvalidData, "no certificate found in the cert file")));
    }
    let key = PrivateKeyDer::from_pem_file(&key_path).map_err(pem_error).map_err(load_error)?;

    let mut warnings = Vec::new();
    let mut crl_next_updates = Vec::new();
    let client_auth = tls.client_auth.as_ref().filter(|c| c.mode != ClientAuthMode::Off);

    let builder = ServerConfig::builder();
    let mut config = match client_auth {
        None => builder.with_no_client_auth().with_single_cert(certs, key),
        Some(client_auth) => {
            let verifier = build_client_verifier(client_auth, tls_base, &mut crl_next_updates, &mut warnings)?;
            builder.with_client_cert_verifier(verifier).with_single_cert(certs, key)
        }
    }
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid TLS cert/key ({}, {}): {e}", cert_path.display(), key_path.display()),
        )
    })?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    if client_auth.is_some() {
        // Revocation and CA changes only get evaluated on a full handshake
        // (rustls resumes a session with the identity it originally
        // authenticated) — with resumption off, every connection pays one.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
    }

    Ok(BuiltTls {
        config: Arc::new(config),
        crl_next_updates,
        warnings,
    })
}

fn build_client_verifier(
    client_auth: &ClientAuthConfig,
    tls_base: &Path,
    crl_next_updates: &mut Vec<(PathBuf, DateTime<Utc>)>,
    warnings: &mut Vec<String>,
) -> io::Result<Arc<dyn ClientCertVerifier>> {
    let ca_rel = client_auth.ca_path.as_deref().unwrap_or_default();
    let ca_path = tls_base.join(ca_rel);
    let ca_error = |e: io::Error| io::Error::new(e.kind(), format!("failed to load tls.clientAuth.caPath ({}): {e}", ca_path.display()));
    let ca_certs = CertificateDer::pem_file_iter(&ca_path)
        .map_err(pem_error)
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>().map_err(pem_error))
        .map_err(ca_error)?;
    if ca_certs.is_empty() {
        return Err(ca_error(io::Error::new(io::ErrorKind::InvalidData, "no certificate found in the CA bundle")));
    }
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "tls.clientAuth.caPath ({}) holds a certificate that can't be used as a trust anchor: {e}",
                    ca_path.display()
                ),
            )
        })?;
    }

    let mut crls = Vec::new();
    for crl_rel in &client_auth.crl_paths {
        let crl_path = tls_base.join(crl_rel);
        let crl_error = |detail: String| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to load tls.clientAuth.crlPaths entry ({}): {detail}", crl_path.display()),
            )
        };
        let bytes =
            std::fs::read(&crl_path).map_err(|e| io::Error::new(e.kind(), format!("failed to read tls.clientAuth.crlPaths entry ({}): {e}", crl_path.display())))?;
        let looks_like_pem = bytes.windows(10).any(|w| w == b"-----BEGIN");
        let file_crls: Vec<CertificateRevocationListDer<'static>> = if looks_like_pem {
            CertificateRevocationListDer::pem_slice_iter(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| crl_error(e.to_string()))?
        } else {
            vec![CertificateRevocationListDer::from(bytes.clone())]
        };
        if file_crls.is_empty() {
            return Err(crl_error("no X509 CRL block found".to_string()));
        }
        for crl in file_crls {
            let (_, parsed) = CertificateRevocationList::from_der(crl.as_ref()).map_err(|_| crl_error("not a parseable CRL".to_string()))?;
            if let Some(next_update) = parsed.next_update()
                && let Some(next_update) = DateTime::from_timestamp(next_update.timestamp(), 0)
            {
                crl_next_updates.push((crl_path.clone(), next_update));
            }
            crls.push(crl);
        }
    }

    if crls.is_empty() {
        warnings.push("clientAuth: no crlPaths configured — certificate revocation is NOT checked".to_string());
    }
    if !client_auth.effective_require_client_auth_eku() {
        warnings.push("clientAuth: requireClientAuthEku is false — a client certificate with no extendedKeyUsage extension is accepted".to_string());
    }

    let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(roots));
    if client_auth.mode == ClientAuthMode::Optional {
        verifier_builder = verifier_builder.allow_unauthenticated();
    }
    if !crls.is_empty() {
        verifier_builder = verifier_builder.with_crls(crls);
        verifier_builder = match client_auth.effective_crl_policy() {
            CrlPolicy::FailClosed => verifier_builder.enforce_revocation_expiration(),
            CrlPolicy::BestEffort => verifier_builder.allow_unknown_revocation_status(),
        };
    }
    let inner = verifier_builder.build().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tls.clientAuth: failed to build the client certificate verifier: {e}"),
        )
    })?;

    Ok(Arc::new(EkuEnforcingVerifier {
        inner,
        require_eku: client_auth.effective_require_client_auth_eku(),
    }))
}

/// Wraps rustls's `WebPkiClientVerifier` to (a) require the `clientAuth`
/// extended key usage on the leaf when configured, and (b) reject — as a
/// handshake failure, not a later request error — a leaf whose identity
/// fields `ClientCertIdentity::from_der` refuses (oversized, control
/// characters, ...). Every other method delegates untouched, so
/// `optional`/`required` and the signature checks behave exactly as the
/// inner verifier decides, and the inner chain/revocation check always runs
/// first.
#[derive(Debug)]
struct EkuEnforcingVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    require_eku: bool,
}

impl ClientCertVerifier for EkuEnforcingVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], now: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self.inner.verify_client_cert(end_entity, intermediates, now)?;

        if self.require_eku {
            match leaf_client_auth_eku(end_entity) {
                Ok(Some(true)) => {}
                Ok(_) => return Err(rustls::Error::InvalidCertificate(CertificateError::InvalidPurpose)),
                Err(e) => return Err(rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))),
            }
        }
        ClientCertIdentity::from_der(end_entity).map_err(|e| rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e)))))?;

        Ok(verified)
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

/// How one loaded CRL stands relative to `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlStatus {
    /// Its `nextUpdate` has already passed.
    Expired,
    /// Its `nextUpdate` is within `CRL_EXPIRY_WARNING_DAYS`.
    ExpiringSoon,
}

/// Every CRL that is expired or about to be, in input order. Pure (takes
/// `now`) so it's testable without a clock.
pub fn crl_freshness(next_updates: &[(PathBuf, DateTime<Utc>)], now: DateTime<Utc>) -> Vec<(PathBuf, DateTime<Utc>, CrlStatus)> {
    let horizon = now + chrono::Duration::days(CRL_EXPIRY_WARNING_DAYS);
    next_updates
        .iter()
        .filter_map(|(path, next_update)| {
            if *next_update <= now {
                Some((path.clone(), *next_update, CrlStatus::Expired))
            } else if *next_update <= horizon {
                Some((path.clone(), *next_update, CrlStatus::ExpiringSoon))
            } else {
                None
            }
        })
        .collect()
}

/// Logs the startup-time freshness findings for `serve`.
pub fn warn_about_crl_freshness(next_updates: &[(PathBuf, DateTime<Utc>)], fail_closed: bool) {
    for (path, next_update, status) in crl_freshness(next_updates, Utc::now()) {
        match status {
            CrlStatus::Expired if fail_closed => tracing::error!(
                "clientAuth: CRL {} expired at {next_update} and crlPolicy is failClosed — every client presenting a certificate is rejected until it is replaced and the server restarted",
                path.display()
            ),
            CrlStatus::Expired => tracing::warn!("clientAuth: CRL {} expired at {next_update} — revocations since then are not seen", path.display()),
            CrlStatus::ExpiringSoon => tracing::warn!(
                "clientAuth: CRL {} expires at {next_update} (within {CRL_EXPIRY_WARNING_DAYS} days) — replace it and restart before then",
                path.display()
            ),
        }
    }
}

/// Sleeps until the earliest not-yet-passed `nextUpdate` and logs one
/// warning, so a long-running server notices a CRL lapsing without anyone
/// restarting it. `None` when there's nothing left to wait for.
pub fn spawn_crl_expiry_watch(next_updates: &[(PathBuf, DateTime<Utc>)]) -> Option<tokio::task::JoinHandle<()>> {
    let now = Utc::now();
    let (path, when) = next_updates.iter().filter(|(_, t)| *t > now).min_by_key(|(_, t)| *t)?.clone();
    let wait = (when - now).to_std().ok()?;
    Some(tokio::spawn(async move {
        tokio::time::sleep(wait).await;
        tracing::warn!("clientAuth: CRL {} has now expired — replace it and restart the server", path.display());
    }))
}

/// Wraps axum-server's `RustlsAcceptor`: after the handshake, parses the
/// peer's leaf certificate (already chain-validated by the verifier above)
/// into a `ClientCertIdentity` and wraps the per-connection service so every
/// request on that connection carries it as an extension. The extension is
/// set only here — never from a header.
#[derive(Clone)]
pub struct ClientCertAcceptor<A> {
    inner: A,
}

impl<A> ClientCertAcceptor<A> {
    pub fn new(inner: A) -> Self {
        ClientCertAcceptor { inner }
    }
}

impl<A, I, S, IO> Accept<I, S> for ClientCertAcceptor<A>
where
    A: Accept<I, S, Stream = TlsStream<IO>>,
    A::Future: Send + 'static,
    A::Service: Send + 'static,
    IO: Send + 'static,
{
    type Stream = TlsStream<IO>;
    type Service = IdentityService<A::Service>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let handshake = self.inner.accept(stream, service);
        Box::pin(async move {
            let (tls, service) = handshake.await.inspect_err(|e| tracing::debug!(error = %e, "TLS handshake failed"))?;
            let identity = match tls.get_ref().1.peer_certificates().and_then(|chain| chain.first()) {
                Some(leaf) => Some(Arc::new(ClientCertIdentity::from_der(leaf).map_err(|e| {
                    tracing::debug!(error = %e, "rejecting a connection whose client certificate has unusable identity fields");
                    io::Error::new(io::ErrorKind::InvalidData, e)
                })?)),
                None => None,
            };
            Ok((tls, IdentityService { inner: service, identity }))
        })
    }
}

/// Per-connection service wrapper. Always strips any identity extension a
/// request arrives with before inserting this connection's own (or leaving
/// none), so nothing upstream of it can ever smuggle one in.
#[derive(Clone)]
pub struct IdentityService<S> {
    inner: S,
    identity: Option<Arc<ClientCertIdentity>>,
}

impl<S, B> tower_service::Service<Request<B>> for IdentityService<S>
where
    S: tower_service::Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        request.extensions_mut().remove::<Arc<ClientCertIdentity>>();
        if let Some(identity) = &self.identity {
            request.extensions_mut().insert(identity.clone());
        }
        self.inner.call(request)
    }
}

#[cfg(test)]
mod tests;
