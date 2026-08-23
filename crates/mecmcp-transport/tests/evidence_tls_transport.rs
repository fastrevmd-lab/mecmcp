//! The evidence sink must be able to reach a TLS-only ClickHouse.
//!
//! `StdHttpTransport` speaks plain HTTP only, and ct104 answers on 8443 with
//! TLS and nothing on 8123 — so with that transport the whole pipeline could
//! never have delivered a row, whatever credentials were deployed
//! (mecmcp#292).
//!
//! This lives in `mecmcp-transport` rather than `mecmcp-audit` because it needs
//! a rustls crypto provider, and that choice is already made and documented
//! here. Making it twice is how aws-lc-rs got linked into a ring build and
//! broke TLS in a downstream server.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::sinks::ssdf::{HttpRequest, HttpTransport};
use mecmcp_transport::evidence_transport::EvidenceHttpTransport;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;

/// A one-shot TLS server that answers any request with `body`.
fn serve_once(cert: rcgen::CertifiedKey, body: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let certs = vec![rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = rustls::StreamOwned::new(connection, stream);
        // Drain the request head so the client's write completes.
        {
            let mut reader = BufReader::new(&mut tls);
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                if line == "\r\n" || line == "\n" {
                    break;
                }
                line.clear();
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _unused = tls.write_all(response.as_bytes());
        let _unused = tls.flush();
        // Close cleanly, so this test exercises the ordinary path rather than
        // the unclean-EOF tolerance.
        tls.conn.send_close_notify();
        let _unused = tls.flush();
    });
    (port, handle)
}

/// An https endpoint is reached, using the supplied private CA as the anchor.
#[test]
fn an_https_endpoint_is_reachable_with_a_private_ca() {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let ca_pem = issued.cert.pem();
    let directory = tempfile::tempdir().unwrap();
    let ca_file = directory.path().join("ca.pem");
    std::fs::write(&ca_file, &ca_pem).unwrap();

    let (port, server) = serve_once(issued, "sha256:tail\n");
    let transport = EvidenceHttpTransport::new(Some(&ca_file)).unwrap();

    let body = transport
        .send(&HttpRequest {
            url: format!("https://localhost:{port}/?query=SELECT+1"),
            method: "POST".to_string(),
            headers: vec![("Authorization".to_string(), "Basic x".to_string())],
            body: Vec::new(),
        })
        .expect("a TLS endpoint with a trusted CA must be reachable");

    assert_eq!(body, "sha256:tail\n");
    server.join().unwrap();
}

/// A certificate the CA does not vouch for is refused.
///
/// Without this the transport would accept any server presenting any
/// certificate, and the audit trail's destination could be substituted by
/// anything on the path.
#[test]
fn an_untrusted_certificate_is_refused() {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let unrelated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let ca_file = directory.path().join("ca.pem");
    std::fs::write(&ca_file, unrelated.cert.pem()).unwrap();

    let (port, server) = serve_once(issued, "never read");
    let transport = EvidenceHttpTransport::new(Some(&ca_file)).unwrap();

    let error = transport
        .send(&HttpRequest {
            url: format!("https://localhost:{port}/?query=SELECT+1"),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect_err("a certificate outside the trust anchor must be refused");
    assert!(
        format!("{error}").to_lowercase().contains("certificate")
            || format!("{error}").to_lowercase().contains("tls"),
        "the error should name the TLS failure: {error}"
    );
    let _unused = server.join();
}

/// Plain http still works, so one transport serves both.
#[test]
fn a_plain_http_endpoint_still_works() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        {
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                if line == "\r\n" || line == "\n" {
                    break;
                }
                line.clear();
            }
        }
        let _unused = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });

    let transport = EvidenceHttpTransport::new(None).unwrap();
    let body = transport
        .send(&HttpRequest {
            url: format!("http://127.0.0.1:{port}/ping"),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .unwrap();

    assert_eq!(body, "ok");
    server.join().unwrap();
}

/// An https endpoint with no CA configured is refused, never downgraded.
///
/// Downgrading would put the audit writer's password on the wire in clear, to
/// a destination nothing authenticated. Failing to deliver is recoverable —
/// segments stay spooled; leaking the credential is not.
#[test]
fn an_https_endpoint_without_a_ca_is_refused_not_downgraded() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Accept and read whatever arrives, so a downgrade would visibly succeed
    // rather than failing on a closed port.
    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut sink = Vec::new();
            let _unused = std::io::Read::read_to_end(&mut stream, &mut sink);
            let _unused = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });

    let transport = EvidenceHttpTransport::new(None).unwrap();
    let error = transport
        .send(&HttpRequest {
            url: format!("https://127.0.0.1:{port}/?query=SELECT+1"),
            method: "POST".to_string(),
            headers: vec![("Authorization".to_string(), "Basic secret".to_string())],
            body: Vec::new(),
        })
        .expect_err("https with no CA must not be sent in clear");

    assert!(
        format!("{error}").contains("no CA"),
        "the error must say why it refused: {error}"
    );
    drop(server);
}

/// A CA file holding no certificate is refused at construction.
///
/// An empty trust store trusts nothing, so every handshake fails — but it fails
/// later, per delivery, looking like an outage rather than a typo in a path.
#[test]
fn an_empty_ca_file_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let ca_file = directory.path().join("ca.pem");
    std::fs::write(&ca_file, "# no certificate here\n").unwrap();

    let Err(error) = EvidenceHttpTransport::new(Some(&ca_file)) else {
        panic!("a CA file with no certificate must be refused")
    };

    assert!(
        format!("{error}").contains("no certificate"),
        "the error must name the problem: {error}"
    );
}
