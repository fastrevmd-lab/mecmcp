//! Secure PEM loading for the Streamable HTTP listener.

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const MAX_CERT_BYTES: u64 = 1024 * 1024;
const MAX_KEY_BYTES: u64 = 128 * 1024;

/// Listener TLS configuration failure.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// File read or metadata error.
    #[error("TLS file I/O at '{}': {error}", path.display())]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        error: std::io::Error,
    },
    /// Unsafe filesystem metadata.
    #[error("unsafe TLS file '{}': {message}", path.display())]
    UnsafeFile {
        /// Affected path.
        path: PathBuf,
        /// Safe diagnostic.
        message: String,
    },
    /// PEM or certificate/key mismatch.
    #[error("invalid TLS configuration: {0}")]
    Invalid(String),
}

/// Load a certificate chain and private key into a TLS 1.2+ rustls server.
///
/// Decision D4: the crypto provider is passed as a parameter, never selected by
/// this crate. Both current consumers use `ring`; they pass
/// `rustls::crypto::ring::default_provider()`.
///
/// Equivalent to [`load_with_client_auth`] with `client_ca_path: None` — no
/// client certificate is requested or required. Kept as a separate entry
/// point so existing callers see no signature change when mTLS is not in use.
pub fn load(
    cert_path: &Path,
    key_path: &Path,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    load_with_client_auth(cert_path, key_path, None, provider)
}

/// As [`load`], with optional mutual TLS.
///
/// When `client_ca_path` is `Some`, the listener requires every client to
/// present a certificate that chains to one of the CAs in that PEM bundle;
/// a handshake from a client without one is rejected by rustls before any
/// application code — including rate limiting and bearer auth — runs.
///
/// When `client_ca_path` is `None`, this is behaviorally identical to
/// [`load`]: no client certificate is requested. mTLS is opt-in per listener,
/// never inferred, so a caller that never passes `Some` sees zero behavior
/// change.
///
/// No CRL is consulted: any certificate chaining to `client_ca_path` is
/// accepted for the CA bundle's lifetime. Revoking a client means rotating
/// the CA (or removing it from the bundle), not blocklisting a serial.
pub fn load_with_client_auth(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let cert_bytes = read_regular(cert_path, MAX_CERT_BYTES, false)?;
    let key_bytes = Zeroizing::new(read_regular(key_path, MAX_KEY_BYTES, true)?);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<_, _>>()
        .map_err(|error| TlsError::Invalid(format!("certificate PEM: {error}")))?;
    if certs.is_empty() {
        return Err(TlsError::Invalid(
            "certificate PEM contains no certificates".to_owned(),
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .map_err(|error| TlsError::Invalid(format!("private-key PEM: {error}")))?;

    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| TlsError::Invalid(format!("TLS versions: {error}")))?;

    let config = match client_ca_path {
        None => builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|error| TlsError::Invalid(format!("certificate/key: {error}")))?,
        Some(ca_path) => {
            let ca_bytes = read_regular(ca_path, MAX_CERT_BYTES, false)?;
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(&ca_bytes) {
                let cert =
                    cert.map_err(|error| TlsError::Invalid(format!("client CA PEM: {error}")))?;
                roots.add(cert).map_err(|error| {
                    TlsError::Invalid(format!("client CA certificate: {error}"))
                })?;
            }
            if roots.is_empty() {
                return Err(TlsError::Invalid(
                    "client CA PEM contains no certificates".to_owned(),
                ));
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|error| TlsError::Invalid(format!("client verifier: {error}")))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|error| TlsError::Invalid(format!("certificate/key: {error}")))?
        }
    };
    Ok(Arc::new(config))
}

fn read_regular(path: &Path, maximum: u64, private: bool) -> Result<Vec<u8>, TlsError> {
    #[cfg(unix)]
    let file = {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| io_error(path, error.into()))?;
        fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = fs::File::open(path).map_err(|error| io_error(path, error))?;

    let metadata = file.metadata().map_err(|error| io_error(path, error))?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(TlsError::UnsafeFile {
            path: path.to_path_buf(),
            message: format!("must be a regular file no larger than {maximum} bytes"),
        });
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(TlsError::UnsafeFile {
                path: path.to_path_buf(),
                message: format!(
                    "private key mode {mode:04o} permits group/other access; use chmod 0600 '{}'",
                    path.display()
                ),
            });
        }
        let owner = metadata.uid();
        let effective = rustix::process::geteuid().as_raw();
        if owner != effective && owner != 0 {
            return Err(TlsError::UnsafeFile {
                path: path.to_path_buf(),
                message: format!(
                    "private key owner uid {owner} is neither effective uid {effective} nor root"
                ),
            });
        }
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(maximum as usize));
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    if bytes.len() as u64 > maximum {
        return Err(TlsError::UnsafeFile {
            path: path.to_path_buf(),
            message: format!("file exceeds {maximum} bytes"),
        });
    }
    Ok(bytes)
}

fn io_error(path: &Path, error: std::io::Error) -> TlsError {
    TlsError::Io {
        path: path.to_path_buf(),
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_matching_self_signed_pair() {
        let issued =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("self signed");
        let directory = tempfile::tempdir().expect("tempdir");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        fs::write(&cert, issued.cert.pem()).expect("cert");
        fs::write(&key, issued.signing_key.serialize_pem()).expect("key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        load(&cert, &key, provider).expect("TLS config");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_world_readable_private_key() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("tempdir");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        fs::write(&cert, "no certificate").expect("cert");
        fs::write(&key, "no key").expect("key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("mode");

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let result = load(&cert, &key, provider);
        assert!(matches!(result, Err(TlsError::UnsafeFile { .. })));

        // Verify the error message names the file, mode, and remedy
        if let Err(TlsError::UnsafeFile { path, message }) = result {
            assert_eq!(path, key);
            assert!(message.contains("0644"), "error should name the mode");
            assert!(message.contains("chmod"), "error should name the remedy");
            assert!(message.contains("0600"), "error should suggest mode 0600");
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_private_key() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("tempdir");
        let cert = directory.path().join("cert.pem");
        let real_key = directory.path().join("real-key.pem");
        let symlink_key = directory.path().join("symlink-key.pem");

        fs::write(&cert, "no certificate").expect("cert");
        fs::write(&real_key, "no key").expect("real key");
        fs::set_permissions(&real_key, fs::Permissions::from_mode(0o600)).expect("mode");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_key, &symlink_key).expect("symlink");

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let result = load(&cert, &symlink_key, provider);
        // O_NOFOLLOW causes open to fail on symlinks with ELOOP
        assert!(matches!(result, Err(TlsError::Io { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn accepts_0600_private_key() {
        use std::os::unix::fs::PermissionsExt;
        let issued =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("self signed");
        let directory = tempfile::tempdir().expect("tempdir");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        fs::write(&cert, issued.cert.pem()).expect("cert");
        fs::write(&key, issued.signing_key.serialize_pem()).expect("key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("mode");

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        load(&cert, &key, provider).expect("0600 key should be accepted");
    }

    /// `client_ca_path: None` must behave exactly like [`load`] — no client
    /// certificate is requested, so a handshake with no client cert succeeds.
    #[tokio::test]
    async fn mtls_off_by_default_admits_a_clientless_handshake() {
        let (server_config, _ca_pem) = build_server_config(None);
        let outcome = handshake(server_config, None).await;
        assert!(
            outcome.is_ok(),
            "a listener built without client_ca_path must accept a client that presents no certificate: {outcome:?}"
        );
    }

    /// Acceptance criterion: mTLS enabled + no client cert -> handshake refused.
    #[tokio::test]
    async fn mtls_enabled_rejects_client_without_certificate() {
        let (server_config, _ca_pem) = build_server_config(Some(()));
        let outcome = handshake(server_config, None).await;
        assert!(
            outcome.is_err(),
            "a listener with client_ca_path configured must refuse a client with no certificate"
        );
    }

    /// Acceptance criterion: mTLS enabled + a cert signed by the configured CA
    /// -> handshake succeeds.
    #[tokio::test]
    async fn mtls_enabled_admits_client_with_certificate_from_configured_ca() {
        let (server_config, ca) = build_server_config(Some(()));
        let client_identity = issue_client_cert(&ca.expect("ca"));
        let outcome = handshake(server_config, Some(client_identity)).await;
        assert!(
            outcome.is_ok(),
            "a client presenting a certificate signed by the configured CA must be admitted: {outcome:?}"
        );
    }

    /// A certificate from an unrelated CA must be refused exactly like no
    /// certificate at all — the point of mTLS is that only the configured CA
    /// is trusted, not "any" client certificate.
    #[tokio::test]
    async fn mtls_enabled_rejects_client_certificate_from_a_different_ca() {
        let (server_config, _ca) = build_server_config(Some(()));
        let unrelated_ca = new_ca();
        let client_identity = issue_client_cert(&unrelated_ca);
        let outcome = handshake(server_config, Some(client_identity)).await;
        assert!(
            outcome.is_err(),
            "a client certificate from a CA the server was not configured with must be refused"
        );
    }

    struct CaIdentity {
        cert_pem: String,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    fn new_ca() -> CaIdentity {
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("empty SAN CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
        let key_pair = rcgen::KeyPair::generate().expect("ca key");
        let cert = params.self_signed(&key_pair).expect("self-signed ca");
        let cert_pem = cert.pem();
        CaIdentity {
            cert_pem,
            issuer: rcgen::Issuer::new(params, key_pair),
        }
    }

    struct ClientIdentity {
        cert_pem: String,
        key_pem: String,
    }

    fn issue_client_cert(ca: &CaIdentity) -> ClientIdentity {
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("client cert params");
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        let key_pair = rcgen::KeyPair::generate().expect("client key");
        let cert = params
            .signed_by(&key_pair, &ca.issuer)
            .expect("ca-signed client cert");
        ClientIdentity {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }

    /// Build a server `ServerConfig` via [`load_with_client_auth`]. When
    /// `require_mtls` is `Some`, the server is configured to trust a freshly
    /// generated CA for client certificates; the CA identity is returned so
    /// tests can issue certificates from it (or deliberately not).
    fn build_server_config(
        require_mtls: Option<()>,
    ) -> (Arc<rustls::ServerConfig>, Option<CaIdentity>) {
        let server_issued =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let directory = tempfile::tempdir().expect("tempdir");
        let cert_path = directory.path().join("server-cert.pem");
        let key_path = directory.path().join("server-key.pem");
        fs::write(&cert_path, server_issued.cert.pem()).expect("write server cert");
        fs::write(&key_path, server_issued.signing_key.serialize_pem()).expect("write server key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("mode");
        }

        let ca = require_mtls.map(|()| new_ca());
        let client_ca_path = ca.as_ref().map(|ca| {
            let path = directory.path().join("client-ca.pem");
            fs::write(&path, &ca.cert_pem).expect("write client ca");
            path
        });
        // `directory` must outlive the `load_with_client_auth` call but the
        // returned config owns no borrow into it, so it is safe to drop here.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config =
            load_with_client_auth(&cert_path, &key_path, client_ca_path.as_deref(), provider)
                .expect("server TLS config");
        (config, ca)
    }

    /// Drive one real TLS handshake: an in-process TCP loopback pair, the
    /// server side terminating with `server_config`, the client side
    /// presenting `client_identity` (or nothing) and trusting the server's
    /// self-signed leaf directly (this test cares about client-auth
    /// enforcement, not server verification).
    async fn handshake(
        server_config: Arc<rustls::ServerConfig>,
        client_identity: Option<ClientIdentity>,
    ) -> Result<(), String> {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("accept");
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            acceptor
                .accept(stream)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        });

        let client_config = build_client_config(client_identity);
        let stream = TcpStream::connect(addr).await.expect("connect");
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let client_result = connector
            .connect(server_name, stream)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string());

        let server_result = server.await.expect("server task");
        client_result.and(server_result)
    }

    /// A client `ClientConfig` that trusts any server certificate (this test
    /// suite is about client-auth enforcement, not server verification) and
    /// presents `client_identity`'s certificate when given one.
    fn build_client_config(client_identity: Option<ClientIdentity>) -> rustls::ClientConfig {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};

        #[derive(Debug)]
        struct AcceptAnyServerCert;

        impl ServerCertVerifier for AcceptAnyServerCert {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("client TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert));

        match client_identity {
            None => builder.with_no_client_auth(),
            Some(identity) => {
                let certs: Vec<CertificateDer<'static>> =
                    CertificateDer::pem_slice_iter(identity.cert_pem.as_bytes())
                        .collect::<Result<_, _>>()
                        .expect("client cert pem");
                let key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes())
                    .expect("client key pem");
                builder
                    .with_client_auth_cert(certs, key)
                    .expect("client auth cert")
            }
        }
    }
}
