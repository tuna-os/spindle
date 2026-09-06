# Telemetry Guidelines & Observability Architecture

## Observability Architecture Assessment

`spindle` implements local-only, opt-in metric exposition and structured log filtering designed for production matrix server operations.

### Key Components

1. **Prometheus Metrics Listener:**
   - Metrics exposition is disabled by default and runs on an isolated opt-in loopback listener when configured (`[metrics] bind = "127.0.0.1:9090"` in server configuration).
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

- **Zero Exporter Policy:** No default OpenTelemetry exporter, Jaeger agent, or external collector endpoint is wired.
- **Local Network Boundary:** All telemetry data stays strictly within local boundaries unless explicitly routed by network operators via local scrapers or reverse proxies.
- **Cardinality Limits:** Custom metrics must maintain bounded label dimensions (e.g., standard HTTP status codes, specific durability modes, or case types) to prevent memory expansion.

## Traces

Distributed tracing exists and is off. It is switched on by naming the
exporter in the config, and by nothing else:

```toml
[logging]
traces = "otlp"
```

With that line the server exports every span it records -- one per
request, named by the matched route, with OpenTelemetry's HTTP semantic
fields -- over OTLP/HTTP with protobuf bodies. The destination is not a
setting in the file: the SDK reads the standard `OTEL_EXPORTER_OTLP_ENDPOINT`
(default `http://localhost:4318`), `OTEL_EXPORTER_OTLP_HEADERS` and
`OTEL_EXPORTER_OTLP_TIMEOUT`, so no collector address is ever hardcoded
and the same config runs against any backend that speaks OTLP. Spans are
batched on a thread of the SDK's own: a slow collector delays no request,
and past the queue spans drop rather than back up.

Without the line, no exporter is built and nothing leaves the process,
which keeps the two rules above true by default. A malformed OTLP
environment fails the start with the SDK's error rather than starting a
server that silently exports nothing.
