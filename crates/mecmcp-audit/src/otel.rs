//! Optional OpenTelemetry tracing/metrics export.
//!
//! Off by default and inert unless configured, matching every other sink in
//! this crate. Two things distinguish it from the audit sinks:
//!
//! - **It is also off at compile time by default.** The `opentelemetry*`
//!   family is roughly ninety additional crates; a server that never sets
//!   `OtelConfig` should not pay for them. [`OtelConfig`] itself is always
//!   compiled (it is plain data), but building an exporter from it is gated
//!   behind the `otel` Cargo feature. A caller that sets [`AuditConfig::otel`]
//!   without that feature enabled gets a startup error, not silence -- see
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

/// How to export traces and metrics.
///
/// Always compiled, whether or not the `otel` feature is enabled, so a
/// server's CLI parsing does not need to be feature-gated too -- only
/// [`build`] is.
///
/// Export cadence is the SDK's own default (a few seconds for traces, 60s for
/// metrics) rather than a field here -- exposing it added two more flags for
/// every server without a deployment yet asking to tune it.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// Base OTLP/HTTP endpoint, e.g. `http://127.0.0.1:4318`. Traces are
    /// exported to `{endpoint}/v1/traces`, metrics to `{endpoint}/v1/metrics`.
    ///
    /// `http://` only -- see the module docs for why. A `https://` value is
    /// refused at [`build`] time rather than silently sent in the clear.
    pub endpoint: String,
    /// The `service.name` resource attribute every span and metric carries.
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
    use opentelemetry_sdk::metrics::SdkMeterProvider;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_subscriber::Layer;
    use tracing_subscriber::registry::LookupSpan;

    /// Holds the providers alive for the process lifetime and flushes them on
    /// shutdown.
    ///
    /// Dropping this without calling [`OtelGuard::shutdown`] still flushes
    /// eventually -- both providers export on their own interval -- but an
    /// orderly shutdown should call it, the same way [`crate::EvidenceService::shutdown`]
    /// flushes its sinks rather than relying on the next interval firing.
    pub struct OtelGuard {
        tracer_provider: SdkTracerProvider,
        meter_provider: SdkMeterProvider,
    }

    impl OtelGuard {
        /// Flush and shut down both providers, best-effort.
        pub fn shutdown(&self) {
            if let Err(error) = self.tracer_provider.shutdown() {
                tracing::warn!(%error, "otel trace provider shutdown failed");
            }
            if let Err(error) = self.meter_provider.shutdown() {
                tracing::warn!(%error, "otel meter provider shutdown failed");
            }
        }
    }

    /// Build the tracing layer and the guard that owns the exporters.
    ///
    /// # Errors
    ///
    /// Returns [`OtelError`] if the endpoint is not `http://`, or if either
    /// exporter fails to construct.
    pub fn build<S>(
        cfg: &OtelConfig,
    ) -> Result<(Box<dyn Layer<S> + Send + Sync>, OtelGuard), OtelError>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync,
    {
        if !cfg.endpoint.starts_with("http://") {
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
            .with_resource(resource.clone())
            .build();

        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_endpoint(format!("{}/v1/metrics", cfg.endpoint.trim_end_matches('/')))
            .build()
            .map_err(|error| OtelError::Setup(error.to_string()))?;
        let meter_provider = SdkMeterProvider::builder()
            .with_periodic_exporter(metric_exporter)
            .with_resource(resource)
            .build();

        let tracer = tracer_provider.tracer(cfg.service_name.clone());
        let layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();

        Ok((
            layer,
            OtelGuard {
                tracer_provider,
                meter_provider,
            },
        ))
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
