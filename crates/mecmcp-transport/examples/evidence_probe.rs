//! Read-only reachability probe for the evidence transport.
//!
//! Answers one question that no unit test can: does this transport complete a
//! TLS handshake with the real ClickHouse, using SSDF's private CA as the
//! anchor? Everything else about the pipeline can be right while this is
//! wrong, and it was wrong until now — the previous transport refused
//! `https://` outright.
//!
//! Sends `GET /ping`, which ClickHouse answers without authentication, so this
//! carries no credential and writes nothing.
//!
//!     cargo run -p mecmcp-transport --example evidence_probe -- \
//!         https://192.168.1.151:8443 /path/to/ssdf-ca.crt

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args
        .next()
        .ok_or("usage: evidence_probe <endpoint> <ca.pem>")?;
    let ca = args
        .next()
        .ok_or("usage: evidence_probe <endpoint> <ca.pem>")?;

    let transport =
        mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(Some(ca.as_ref()))?;
    let body = mecmcp_audit::sinks::ssdf::HttpTransport::send(
        &transport,
        &mecmcp_audit::sinks::ssdf::HttpRequest {
            url: format!("{endpoint}/ping"),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        },
    )?;
    println!("ok: {}", body.trim());
    Ok(())
}
