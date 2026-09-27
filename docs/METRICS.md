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

The metrics token travels in the clear on a plain-HTTP listener the same way
an MCP bearer token does. If you configure a metrics token for a
non-loopback peer, put a TLS terminator in front of the listener — the same
expectation this crate already documents for any off-loopback bind.

Metrics contain aggregate bounded labels only (session counts, limit-hit
reasons, tool names, terminal results). They never contain device names,
hostnames, tokens, or other customer data — that is enforced by what the
four metric series record, not by the access control above, so it holds
regardless of who reaches `/metrics`.

### Behind a reverse proxy

A same-host reverse proxy (nginx, caddy, traefik, a Cloudflare tunnel) — the
deployment shape this project documents for its own MCP servers — makes
every request it forwards arrive at the process with a **loopback** TCP peer,
no matter who reached the proxy. The loopback carve-out cannot tell that
request apart from a local scrape by peer address alone.

To close that gap, a loopback peer that carries a request-forwarding header
(`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`) is treated
as **not** loopback and must present the metrics token like any other remote
caller. Prometheus itself sends none of these headers, so a direct, colocated
scrape is unaffected.

This only helps if your proxy actually sends one of those headers, or if it
never forwards `/metrics` at all — which is the safer default. Block the path
at the proxy:

```nginx
location = /metrics {
    return 404;
}
```

A proxy configured to strip or simply never set forwarding headers (nginx
sends none unless `proxy_set_header` is configured) still passes through
undetected. The header check is defense in depth, not a substitute for not
exposing `/metrics` through the proxy in the first place.

## Migration for existing Prometheus scrapers

If your scraper already runs on the same host as the server (the common
case — a colocated Prometheus or node-exporter-style sidecar), no change is
needed: the scraper's peer address is loopback, and — unless it sits behind a
reverse proxy that forwards `/metrics` — it does not carry a forwarding
header either. If your scraper reaches the server *through* a same-host
reverse proxy, see "Behind a reverse proxy" above: either stop the proxy from
forwarding `/metrics`, or configure a metrics token as below.

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

Both routes sit behind the same Host/Origin validation as `/mcp` and
`/metrics`. A kubelet `httpGet` probe sends `Host: <podIP>:<port>` by
default, which the allowlist rejects unless you add it. Either set
`httpGet.httpHeaders` on the probe to a Host value already in your
`HostOriginPolicy` allowlist, or add the pod IP pattern your platform uses.

A `ReadinessCheck` probe runs synchronously, inline with the request, on an
unauthenticated route that has no per-route rate limit of its own (only the
IP rate limit, if configured). Keep probes cheap and non-blocking — for
example, have the audit sink keep an `AtomicBool` current and read that,
rather than performing a test write per request — or wrap a blocking probe in
`spawn_blocking`.
