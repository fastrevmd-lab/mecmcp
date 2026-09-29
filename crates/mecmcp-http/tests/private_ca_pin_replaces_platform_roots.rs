//! Regression test for the `tls_certs_only` fix (MEC-33 / MEC-58, commit
//! "mecmcp-http: a configured private CA replaces the public root store").
//!
//! The unit test added alongside that fix,
//! `a_configured_private_ca_does_not_also_trust_an_unrelated_one`, cannot tell
//! `tls_certs_only` from the old `tls_certs_merge`/`add_root_certificate`
//! behaviour: both self-signed roots it uses are unknown to the platform/public
//! store either way, so the "unrelated" certificate is rejected by both the
//! fixed and the reverted code, for the same reason a certificate from a real
//! stranger CA would be. The bug this crate fixed was never "an unknown CA is
//! rejected" — it was "a *platform-trusted* CA stays trusted even once an
//! operator pins to a private one".
//!
//! Proving that needs a certificate the platform store genuinely trusts, and a
//! hermetic test cannot fabricate one the real public root store accepts (the
//! PR's own manual verification note says as much). Instead, this test fakes
//! "the platform store" by pointing `SSL_CERT_FILE` at a second, independent
//! self-signed root — `rustls-platform-verifier` (via `rustls-native-certs`)
//! honours that variable as an override for the system store on Linux, and
//! `reqwest`'s `rustls-no-provider` feature (this crate's TLS backend) routes
//! through `rustls-platform-verifier` for exactly this "no `extra_root_certificates`
//! configured" and "`tls_certs_merge`" cases.
//!
//! `SSL_CERT_FILE` has to be set before the client's TLS verifier is built, and
//! the workspace forbids `unsafe_code` — which is what `std::env::set_var`
//! requires on this edition. So this test sets the variable on a *child*
//! process instead (`Command::env`, not `set_var`), and does the actual
//! client/server exchange there. The parent's job is only to generate the
//! certificates, run the server, launch that child twice, and check its exit
//! status.
//!
//! Linux-only: it relies on `rustls-native-certs`' `SSL_CERT_FILE` override,
//! which is a Unix-only mechanism, and this is the deploy target.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, reason = "test code")]

use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
use mecmcp_openapi::expand_path;
use rustls::pki_types::CertificateDer;
use std::process::{Command, Output};
use std::sync::Arc;

/// Set (to any value) only in the child process this test re-execs itself as.
const CHILD_ENV: &str = "MECMCP_HTTP_CA_PIN_TEST_CHILD";
/// TCP port of the local TLS server the child must connect to.
const PORT_ENV: &str = "MECMCP_HTTP_CA_PIN_TEST_PORT";
/// PEM of the operator's configured private CA. Present only for the "pinned"
/// leg; its absence means "build an unpinned client".
const PINNED_CA_ENV: &str = "MECMCP_HTTP_CA_PIN_TEST_PINNED_CA_PEM";

#[test]
fn private_ca_pin_replaces_platform_roots() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_child();
        return;
    }
    run_parent();
}

/// Generates certs, runs the two child legs, and asserts on their outcome.
fn run_parent() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime for test server");
    rt.block_on(async {
        // Stands in for a certificate the real platform/public root store
        // trusts. The child's `SSL_CERT_FILE` points at this, and it is also
        // what the test server presents — so an unpinned client trusts it
        // only if the platform-store override actually took effect.
        let (platform_ca_pem, platform_cert_der, platform_key_der) = generate_self_signed();
        // The operator's configured private CA. It never signs anything the
        // server presents, so no client should ever validate the server
        // through it — the point is to prove a pinned client refuses to fall
        // back to the platform store instead.
        let (configured_ca_pem, _unused_cert_der, _unused_key_der) = generate_self_signed();

        let dir = tempfile::tempdir().expect("tempdir");
        let platform_ca_path = dir.path().join("platform-ca.pem");
        std::fs::write(&platform_ca_path, &platform_ca_pem).expect("write platform CA pem");

        // Sanity leg: if an unpinned client does not trust the faked platform
        // CA, the harness itself is broken and the pinned leg below proves
        // nothing either way.
        let (listener, port) = bind_local().await;
        serve(
            listener,
            build_server_config(platform_cert_der.clone(), &platform_key_der),
        );
        let unpinned = spawn_child(&platform_ca_path, port, None);
        assert!(
            unpinned.status.success(),
            "sanity check failed: an unpinned client must trust a server whose certificate \
             the platform root store (faked via SSL_CERT_FILE) recognizes\n--- child stdout ---\n{}\n--- child stderr ---\n{}",
            String::from_utf8_lossy(&unpinned.stdout),
            String::from_utf8_lossy(&unpinned.stderr),
        );

        // The regression check: a client pinned to a private CA that never
        // issued the server's certificate must refuse it, even though the
        // platform store (faked via the same SSL_CERT_FILE) would happily
        // vouch for it. `tls_certs_merge`/`add_root_certificate` fails this by
        // construction, because it keeps the platform store trusted alongside
        // the pin; only `tls_certs_only` disables it.
        let (listener, port) = bind_local().await;
        serve(
            listener,
            build_server_config(platform_cert_der, &platform_key_der),
        );
        let pinned = spawn_child(&platform_ca_path, port, Some(&configured_ca_pem));
        assert!(
            pinned.status.success(),
            "a private-CA-pinned client must not fall back to the platform root store: it \
             validated a certificate its configured CA never issued\n--- child stdout ---\n{}\n--- child stderr ---\n{}",
            String::from_utf8_lossy(&pinned.stdout),
            String::from_utf8_lossy(&pinned.stderr),
        );
    });
}

/// Re-exec this test binary as a child with `SSL_CERT_FILE` set.
///
/// `pinned_ca_pem` is `None` for the unpinned leg and `Some` for the pinned
/// one. Re-running the whole binary (rather than mutating this process's
/// environment) is required, not just convenient: `SSL_CERT_FILE` must be in
/// place before `rustls-native-certs` first reads it, and setting a variable
/// on the current process needs `unsafe`, which this workspace forbids.
fn spawn_child(
    platform_ca_path: &std::path::Path,
    port: u16,
    pinned_ca_pem: Option<&str>,
) -> Output {
    let exe = std::env::current_exe().expect("current test binary path");
    let mut command = Command::new(exe);
    command
        .env(CHILD_ENV, "1")
        .env("SSL_CERT_FILE", platform_ca_path)
        .env(PORT_ENV, port.to_string());
    if let Some(pem) = pinned_ca_pem {
        command.env(PINNED_CA_ENV, pem);
    } else {
        command.env_remove(PINNED_CA_ENV);
    }
    command.output().expect("spawn child test process")
}

/// The child's whole job: build one `HttpClient` and try one request.
///
/// Panicking (via `assert!`) is deliberate — libtest turns that into a
/// non-zero exit code, which is all the parent reads.
fn run_child() {
    let port: u16 = std::env::var(PORT_ENV)
        .expect("port env set by parent")
        .parse()
        .expect("port env is a valid u16");
    let pinned_ca_pem = std::env::var(PINNED_CA_ENV).ok();
    let is_pinned = pinned_ca_pem.is_some();

    // Process-global and one-shot, same as the crate's own `ensure_crypto_provider`
    // test helper: `HttpClient::new` refuses to build without one installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime for test client");
    rt.block_on(async {
        let config = HttpClientConfig {
            extra_root_certificates: pinned_ca_pem.into_iter().collect(),
            ..Default::default()
        };
        let client = HttpClient::new(config).expect("client construction must succeed");
        let path = expand_path("/", &[]).expect("static path template always expands");
        let request = HttpRequest::with_base_and_path(
            Method::Get,
            &format!("https://localhost:{port}"),
            &path,
        )
        .expect("request construction must succeed");
        let result = client.send(request).await;

        if is_pinned {
            assert!(
                result.is_err(),
                "a client pinned to a CA that never issued the server's certificate must not \
                 have connected, but got: {result:?}"
            );
        } else {
            assert!(
                result.is_ok(),
                "an unpinned client must trust the faked platform CA, but got: {result:?}"
            );
        }
    });
}

/// Generate a self-signed `localhost` certificate.
///
/// Returns its PEM (usable as a trust anchor) alongside the raw DER pieces
/// needed to build a `rustls::ServerConfig` that presents it, since a fresh
/// `ServerConfig` is needed per server instance but both servers in this test
/// must present the *same* certificate as the one PEM'd into `SSL_CERT_FILE`.
fn generate_self_signed() -> (String, CertificateDer<'static>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let cert_der = cert.der().clone();
    let key_der = key_pair.serialize_der();
    (cert_pem, cert_der, key_der)
}

/// Build a `rustls::ServerConfig` presenting the given certificate/key.
///
/// The provider is named explicitly, not left to auto-detection, for the same
/// reason as the crate's own `tls_material` test helper: under
/// `cargo test --workspace`, feature unification enables more than one rustls
/// crypto provider and auto-detection panics.
fn build_server_config(cert_der: CertificateDer<'static>, key_der: &[u8]) -> rustls::ServerConfig {
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec()).into();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    server_config
}

/// Accept exactly one TLS connection and reply `200 OK` with an empty body.
///
/// `Connection: close` matters: the pool would otherwise try to reuse a socket
/// whose one-shot handler has already returned.
fn serve(listener: tokio::net::TcpListener, server_config: rustls::ServerConfig) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return;
        };
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while tls.read_exact(&mut byte).await.is_ok() {
            seen.push(byte[0]);
            if seen.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = tls
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        let _ = tls.flush().await;
    });
}

async fn bind_local() -> (tokio::net::TcpListener, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}
