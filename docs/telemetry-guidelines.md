# Telemetry Guidelines & Observability Architecture

## Observability Architecture Assessment

`spindle` has local-only, opt-in metric exposition and structured log filters, designed for Matrix servers in production.

### Key Components

1. **Prometheus Metrics Listener:**
   - Metrics exposition is disabled by default. When you configure it, it runs on an isolated, opt-in loopback listener (`[metrics] bind = "127.0.0.1:9090"` in server configuration).
   - Exposes key performance, sync lag, append latency, and state resolution metrics including:
     - `spindle_build_info`: Gauge indicating build version.
     - `spindle_events_appended_total`: Counter tracking events reaching room logs by origin (`local` vs `federated`).
     - `spindle_fork_resolutions_total`: Counter tracking SPEC §9.2 state resolution cases (`case="1"`, `case="2"`, `case="3"`).
     - `spindle_append_duration_seconds`: Histogram measuring durability commit latency.
     - `spindle_http_requests_total` & `spindle_http_request_duration_seconds`: HTTP route metrics.
     - `spindle_sync_subscribers` & `spindle_sync_lag_seconds`: Long-polling `/sync` subscriber and event delivery lag indicators.

2. **Structured Logging Posture:**
   - Utilizes `tracing` and `tracing-subscriber` with `env-filter` support.
   - Verbosity controlled at runtime via `RUST_LOG` environment variables (e.g., `spindle=debug,warn`).

3. **Validation & CI Automation:**
   - `scripts/check-observability-pack.py` verifies metric registration against Prometheus alert definitions (`deploy/prometheus/spindle-alerts.yaml`) and Grafana dashboard schema (`deploy/grafana/spindle.json`).

## Data Flow & Telemetry Boundary Rules

- **Zero Exporter Policy:** Spindle wires no default OpenTelemetry exporter, Jaeger agent, or external collector endpoint.
- **Local Network Boundary:** All telemetry data stays strictly within local boundaries. It leaves only when network operators route it explicitly through local scrapers or reverse proxies.
- **Cardinality Limits:** Custom metrics must keep their label dimensions bounded, to prevent memory expansion. Examples: the standard codes for HTTP status, specific durability modes, or case types.

## Traces

Spindle has distributed traces, and they are off. Only the name of the
exporter in the config switches them on:

```toml
[logging]
traces = "otlp"
```

With that line, the server exports every span it records over OTLP/HTTP
with protobuf bodies. There is one span per request, named by the matched
route, with the HTTP semantic fields of OpenTelemetry.

The destination is not a setting in the file. The SDK reads the standard
`OTEL_EXPORTER_OTLP_ENDPOINT` (default <code>http://localhost:4318</code>),
`OTEL_EXPORTER_OTLP_HEADERS` and `OTEL_EXPORTER_OTLP_TIMEOUT`. So the
config never hardcodes a collector address, and the same config runs
against any backend that speaks OTLP. The SDK batches spans on a thread of
its own, so a slow collector delays no request. When the queue is full,
spans drop and do not back up.

Without the line, Spindle builds no exporter and nothing leaves the
process. This keeps the two rules above true by default. If the OTLP
environment variables are not valid, the start fails with the SDK's error.
Spindle does not start a server that silently exports nothing.
