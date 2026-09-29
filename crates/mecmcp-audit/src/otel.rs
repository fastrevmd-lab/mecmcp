//! Optional OpenTelemetry trace export.
//!
//! Traces only, not metrics: this workspace records metrics through the
//! `metrics` crate, not the OpenTelemetry metrics API, and an OTel meter
//! provider nothing ever records to is a silent no-op export, not a working
//! pipeline. Bridging `metrics` into OTel export is future work, not in
//! scope here.
//!
//! Off by default and inert unless configured, matching every other sink in
//! this crate. Two things distinguish it from the audit sinks:
//!
//! - **It is also off at compile time by default.** The `opentelemetry*`
//!   family is roughly ninety additional crates; a server that never sets
//!   `OtelConfig` should not pay for them. [`OtelConfig`] itself is always
//!   compiled (it is plain data), but building an exporter from it is gated
//!   behind the `otel` Cargo feature. A caller that sets
//!   `AuditConfig::otel` without that feature enabled gets a startup error,
//!   not silence -- see
//!   [`crate::init_tracing`], which applies the same "refuse rather than drop
//!   a requested sink" rule to `--audit-log-file` (#158).
//! - **It only speaks plain HTTP.** `opentelemetry-otlp` is built here with
//!   `default-features = false` and only `http-proto` +
//!   `reqwest-blocking-client`, which pulls `reqwest` with no TLS backend at
//!   all. That is deliberate: choosing a TLS backend is decision D4's
//!   territory (see `mecmcp-transport`'s Cargo.toml), and a second crate
//!   quietly making that choice is how `aws-lc-rs` got linked into a `ring`
//!   build before. A remote collector is reached the same way a remote
//!   ClickHouse is reached without `mecmcp-transport`: through a loopback
//!   TLS-terminating proxy, not by this crate speaking TLS itself.

/// How to export traces.
///
/// Always compiled, whether or not the `otel` feature is enabled, so a
/// server's CLI parsing does not need to be feature-gated too -- only the
/// `otel` feature's `build` function is.
///
/// Export cadence is the SDK's own default (a few seconds) rather than a
/// field here -- exposing it added a flag for every server without a
/// deployment yet asking to tune it.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// Base OTLP/HTTP endpoint, e.g. `http://127.0.0.1:4318`. Traces are
    /// exported to `{endpoint}/v1/traces`.
    ///
    /// `http://` to a loopback IP literal only -- see the module docs for
    /// why. A `https://` value, a non-loopback host, or a hostname (even one
    /// that would resolve to loopback) is refused at export-setup time
    /// rather than silently sent in the clear or trusted on a DNS-rebinding
    /// TOCTOU.
    pub endpoint: String,
    /// The `service.name` resource attribute every span carries.
    pub service_name: String,
}

/// Why OpenTelemetry export could not be set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OtelError {
    /// [`OtelConfig`] was set, but this build was not compiled with the
    /// `otel` feature.
    #[error(
        "otel export was configured, but this build does not have the `otel` feature \
         enabled; rebuild mecmcp-audit with `--features otel`, or remove the otel \
         configuration"
    )]
    NotCompiled,
    /// The endpoint was not `http://`.
    ///
    /// Not a limitation of OTLP itself -- `opentelemetry-otlp`'s HTTP client
    /// can do TLS. It is a limitation of *this* crate deliberately not
    /// depending on a TLS backend of its own (decision D4). A caller that
    /// needs a remote, TLS-protected collector runs a local OTLP proxy that
    /// terminates TLS, the same pattern `SsdfSinkConfig` documents for
    /// ClickHouse.
    #[error(
        "otel endpoint {0:?} is not http://; this crate does not carry its own TLS stack \
         (decision D4) -- point it at a local collector or a loopback TLS-terminating proxy"
    )]
    NotPlainHttp(String),
    /// The exporter or provider could not be constructed.
    #[error("otel exporter setup failed: {0}")]
    Setup(String),
}

#[cfg(feature = "otel")]
mod enabled {
    use super::{OtelConfig, OtelError};
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_subscriber::Layer;
    use tracing_subscriber::registry::LookupSpan;

    /// Holds the tracer provider alive for the process lifetime and flushes
    /// it on shutdown.
    ///
    /// Traces only, not metrics: this crate's workspace records metrics
    /// through the `metrics` crate, not the OpenTelemetry metrics API, so an
    /// `SdkMeterProvider` here would sit unconnected to anything that ever
    /// records to it -- an empty periodic export on a timer, not a working
    /// metrics pipeline. Bridging `metrics` into OTel metrics export is a
    /// separate, larger piece of work than "give traces an export path";
    /// this stays traces-only until that is scoped.
    ///
    /// Dropping this without calling [`OtelGuard::shutdown`] still flushes
    /// eventually -- the provider exports on its own batch interval -- but an
    /// orderly shutdown should call it, the same way [`crate::EvidenceService::shutdown`]
    /// flushes its sinks rather than relying on the next interval firing.
    pub struct OtelGuard {
        tracer_provider: SdkTracerProvider,
    }

    impl OtelGuard {
        /// Flush and shut down the tracer provider, best-effort.
        pub fn shutdown(&self) {
            if let Err(error) = self.tracer_provider.shutdown() {
                tracing::warn!(%error, "otel trace provider shutdown failed");
            }
        }
    }

    /// Build the tracing layer and the guard that owns the exporter.
    ///
    /// # Errors
    ///
    /// Returns [`OtelError`] if the endpoint is not `http://` to a loopback
    /// host, or if the exporter fails to construct.
    pub fn build<S>(
        cfg: &OtelConfig,
    ) -> Result<(Box<dyn Layer<S> + Send + Sync>, OtelGuard), OtelError>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync,
    {
        if !cfg.endpoint.starts_with("http://") {
            return Err(OtelError::NotPlainHttp(cfg.endpoint.clone()));
        }
        // `http://` alone is not "trusted network". The same rule
        // `SsdfSinkConfig`/`ForwardSinkConfig` apply to their endpoints
        // applies here for the same reason: plaintext OTLP carries span
        // attributes and event bodies (device names, tool args, and whatever
        // a downstream crate's `debug!` puts in scope) on the wire in the
        // clear, so a non-loopback host is a data leak to anyone on the path.
        // `split_endpoint` refuses that, and refuses hostnames rather than
        // resolving them, closing the same DNS-rebinding TOCTOU it closes for
        // SSDF. It cannot return `tls == true` here since a `https://`
        // endpoint was already refused above; the check exists so this stays
        // correct if that ordering ever changes.
        let (tls, ..) = crate::sinks::ssdf::split_endpoint(&cfg.endpoint)
            .map_err(|error| OtelError::Setup(error.to_string()))?;
        if tls {
            return Err(OtelError::NotPlainHttp(cfg.endpoint.clone()));
        }

        let resource = Resource::builder()
            .with_service_name(cfg.service_name.clone())
            .build();

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_endpoint(format!("{}/v1/traces", cfg.endpoint.trim_end_matches('/')))
            .build()
            .map_err(|error| OtelError::Setup(error.to_string()))?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_resource(resource)
            .build();

        let tracer = tracer_provider.tracer(cfg.service_name.clone());
        let layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();

        Ok((layer, OtelGuard { tracer_provider }))
    }
}

#[cfg(feature = "otel")]
pub use enabled::{OtelGuard, build};

#[cfg(all(test, feature = "otel"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn an_https_endpoint_is_refused() {
        let cfg = OtelConfig {
            endpoint: "https://collector.example:4318".to_string(),
            service_name: "test".to_string(),
        };
        let error = match build::<tracing_subscriber::Registry>(&cfg) {
            Err(error) => error,
            Ok(_) => panic!("an https:// endpoint must be refused"),
        };
        assert!(matches!(error, OtelError::NotPlainHttp(_)));
    }

    #[test]
    fn a_plain_http_endpoint_to_a_non_loopback_host_is_refused() {
        // Regression test for a review finding (MEC-459): `http://` alone was
        // being accepted regardless of host, so a configured collector on the
        // network sent every span and metric -- including whatever attributes
        // and bodies a downstream crate attached -- in the clear to anyone on
        // the path.
        let cfg = OtelConfig {
            endpoint: "http://10.9.9.9:4318".to_string(),
            service_name: "test".to_string(),
        };
        let error = match build::<tracing_subscriber::Registry>(&cfg) {
            Err(error) => error,
            Ok(_) => panic!("a plain-http endpoint to a non-loopback host must be refused"),
        };
        assert!(
            error.to_string().contains("non-loopback"),
            "must name the refusal reason: {error}"
        );
    }

    #[test]
    fn a_plain_http_endpoint_to_a_hostname_is_refused() {
        // A hostname is refused even when it would resolve to loopback:
        // resolving it to decide trust is a DNS-rebinding TOCTOU, the same
        // reasoning `split_endpoint` documents for SSDF and the forward sink.
        let cfg = OtelConfig {
            endpoint: "http://localhost:4318".to_string(),
            service_name: "test".to_string(),
        };
        let error = match build::<tracing_subscriber::Registry>(&cfg) {
            Err(error) => error,
            Ok(_) => panic!("a hostname endpoint must be refused"),
        };
        assert!(error.to_string().contains("non-loopback"));
    }

    #[test]
    fn a_plain_http_endpoint_builds_without_a_reachable_collector() {
        // Building the exporter must not require the collector to be up:
        // export happens on its own batched interval, not at construction.
        let cfg = OtelConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            service_name: "test".to_string(),
        };
        let (_layer, guard) = build::<tracing_subscriber::Registry>(&cfg).unwrap();
        guard.shutdown();
    }
}
