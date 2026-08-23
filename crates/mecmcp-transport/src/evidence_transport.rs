//! A TLS-capable HTTP transport for the SSDF evidence sink.
//!
//! `mecmcp-audit`'s own transport speaks plain HTTP only, and the ClickHouse it
//! must reach answers on 8443 with TLS and nothing on 8123 — so the evidence
//! pipeline could never have delivered a row with that transport, whatever
//! credentials were deployed (mecmcp#292).
//!
//! **Why here and not in `mecmcp-audit`.** TLS means choosing a rustls crypto
//! provider. That choice is already made in this crate and documented as
//! decision D4, taken after aws-lc-rs was linked into a `ring` build and broke
//! TLS in a downstream server. Making the same choice a second time, in a crate
//! that does not know it has been made, is how that happens again. This crate
//! already depends on `mecmcp-audit`, so the direction works out.

use std::path::Path;
use std::sync::Arc;

use mecmcp_audit::sinks::ssdf::{HttpRequest, HttpTransport, SsdfSinkError};
use rustls::pki_types::pem::PemObject;

/// An HTTP transport that speaks TLS when the endpoint asks for it.
pub struct EvidenceHttpTransport {
    client: Option<Arc<rustls::ClientConfig>>,
}

impl std::fmt::Debug for EvidenceHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceHttpTransport")
            .field("tls", &self.client.is_some())
            .finish()
    }
}

impl EvidenceHttpTransport {
    /// Build a transport, trusting `ca_file` as the only anchor when given.
    ///
    /// SSDF issues its ClickHouse certificate from a private CA, so the public
    /// root set is useless here and trusting it as well would only widen what
    /// can impersonate the audit destination. When no CA is supplied the
    /// transport is plain-HTTP only, and an `https://` endpoint is refused
    /// rather than silently downgraded.
    ///
    /// # Errors
    ///
    /// Returns [`SsdfSinkError`] if the CA file cannot be read or holds no
    /// usable certificate.
    pub fn new(ca_file: Option<&Path>) -> Result<Self, SsdfSinkError> {
        let Some(ca_file) = ca_file else {
            return Ok(Self { client: None });
        };

        let pem = std::fs::read(ca_file).map_err(|error| {
            SsdfSinkError::Http(format!("reading CA {}: {error}", ca_file.display()))
        })?;
        let mut roots = rustls::RootCertStore::empty();
        let mut added = 0usize;
        for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
            let certificate = certificate.map_err(|error| {
                SsdfSinkError::Http(format!("parsing CA {}: {error}", ca_file.display()))
            })?;
            roots.add(certificate).map_err(|error| {
                SsdfSinkError::Http(format!("adding CA {}: {error}", ca_file.display()))
            })?;
            added += 1;
        }
        if added == 0 {
            return Err(SsdfSinkError::Http(format!(
                "CA file {} holds no certificate; delivery would trust nothing and \
                 every attempt would fail at the handshake",
                ca_file.display()
            )));
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| SsdfSinkError::Http(format!("TLS versions: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Self {
            client: Some(Arc::new(client)),
        })
    }
}

impl HttpTransport for EvidenceHttpTransport {
    fn send(&self, request: &HttpRequest) -> Result<String, SsdfSinkError> {
        let (tls, host, port, path) = mecmcp_audit::sinks::ssdf::split_endpoint(&request.url)?;
        let mut stream = mecmcp_audit::sinks::ssdf::connect(&host, port)?;

        if !tls {
            return mecmcp_audit::sinks::ssdf::exchange(&mut stream, &host, &path, request);
        }

        let Some(client) = self.client.clone() else {
            return Err(SsdfSinkError::Http(format!(
                "{} is https but no CA was configured; refusing rather than \
                 downgrading, which would send the audit credential in clear",
                request.url
            )));
        };
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|error| SsdfSinkError::Http(format!("invalid server name {host}: {error}")))?
            .to_owned();
        let connection = rustls::ClientConnection::new(client, server_name)
            .map_err(|error| SsdfSinkError::Http(format!("TLS setup for {host}: {error}")))?;
        let mut tls_stream = rustls::StreamOwned::new(connection, stream);
        mecmcp_audit::sinks::ssdf::exchange(&mut tls_stream, &host, &path, request)
    }
}
