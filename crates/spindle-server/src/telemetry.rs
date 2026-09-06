//! Spans out of the process, when an operator asks (#19).
//!
//! The log already carries every span `tracing` records; this is the
//! exporter for a backend that draws them as traces. Off by default and
//! off unless `[logging] traces = "otlp"` names it, per
//! `docs/telemetry-guidelines.md`: no collector address is hardcoded and
//! none is defaulted here beyond what the OTLP environment variables
//! themselves default to, so an operator who has not configured a
//! collector has a server that sends nothing anywhere.

use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;

/// A tracer provider exporting over OTLP/HTTP to the endpoint
/// `OTEL_EXPORTER_OTLP_ENDPOINT` names.
///
/// Batched on a thread of the SDK's own, so a slow collector delays
/// nothing on a request path: spans queue and, past the queue, drop.
///
/// # Errors
///
/// Returns the exporter's own error text if it cannot be built, which is
/// an environment variable it could not parse; there is no network at
/// build time, so an unreachable collector is not an error here but a
/// warning the SDK logs when the first batch fails.
pub fn otlp_provider() -> Result<SdkTracerProvider, String> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
        .map_err(|error| error.to_string())?;
    let resource = Resource::builder()
        .with_service_name("spindle")
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build();
    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build())
}
