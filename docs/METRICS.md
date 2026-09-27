# Prometheus metrics (`mecmcp-transport`)

`/metrics` is opt-in, enabled per server with
`HttpTransportConfig::with_metrics(true)`. It is never protected by MCP
bearer authentication — MCP tokens authorize tool calls, not the metrics
surface — so `mecmcp-transport` gives `/metrics` its own access control.

## Security

**Default: loopback-only.** A peer that is not `127.0.0.1` or `::1` gets a
403, regardless of any MCP bearer token it presents. This is a behaviour
change from earlier releases, where `/metrics` was reachable by anyone who
could reach the listener (subject only to the Host/Origin allowlist and the
IP rate limit).

**Optional: a dedicated metrics token.** Call
`HttpTransportConfig::with_metrics_token(digest)` with a
`mecmcp_auth::TokenDigest` to also admit a non-loopback peer that presents
that token's plaintext as its own bearer credential
(`Authorization: Bearer <token>`). Mint the plaintext with
`mecmcp_auth::TokenSecret::mint()`; store only the digest. This token is
checked independently of the MCP bearer token store — an MCP token never
grants `/metrics`, and a metrics token never grants `/mcp`.

Metrics contain aggregate bounded labels only (session counts, limit-hit
reasons, tool names, terminal results). They never contain device names,
hostnames, tokens, or other customer data — that is enforced by what the
four metric series record, not by the access control above, so it holds
regardless of who reaches `/metrics`.

## Migration for existing Prometheus scrapers

If your scraper already runs on the same host as the server (the common
case — a colocated Prometheus or node-exporter-style sidecar), no change is
needed: the scraper's peer address is loopback.

If your scraper is remote, pick one:

- Move the scrape to a process colocated with the server (a sidecar, or a
  local Prometheus federating upstream), or
- Configure a metrics token on the server and add it to the scrape config:

  ```yaml
  scrape_configs:
    - job_name: mecmcp
      metrics_path: /metrics
      authorization:
        credentials_file: /etc/prometheus/mecmcp-metrics-token
      static_configs:
        - targets: ["mcp.example.test:30030"]
  ```

## Liveness and readiness

`/healthz` and `/readyz` are unauthenticated and always mounted — unlike
`/metrics`, they are not opt-in. Neither returns device or customer data.

- `GET /healthz` — the process is up. Consults nothing else.
- `GET /readyz` — 200 when every configured
  [`ReadinessCheck`](../crates/mecmcp-transport/src/health.rs) passes, 503
  listing the failed check names otherwise. `mecmcp-transport` ships with no
  checks configured (and therefore reports ready with none): each consuming
  server wires in its own — audit sink writable, inventory loaded — via
  `HttpTransportConfig::with_readiness_check`.
