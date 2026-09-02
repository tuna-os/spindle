# Runbook: SpindleSyncLagHigh

## Overview
- **Alert Name**: `SpindleSyncLagHigh`
- **Severity**: `warning`
- **Metric**: `spindle_sync_lag_seconds`
- **Condition**: p99 lag of delivered events > 30 seconds over 5 minutes, sustained for 15 minutes.

## Context
`spindle_sync_lag_seconds` measures the age of the newest event delivered to a client in a `/sync` response at the moment of delivery. Elevated sync lag means connected clients are receiving timeline events significantly after they were committed.

## Impact
- Degraded user experience: message delivery and notification lag on Matrix clients (Element, Cinny, etc.).

## Diagnostic Steps
1. Query p99 sync lag in Prometheus:
   ```promql
   histogram_quantile(0.99, sum by (le) (rate(spindle_sync_lag_seconds_bucket[5m])))
   ```
2. Check active subscriber count via `spindle_sync_subscribers`.
3. Check HTTP request latency for `/sync` routes using `spindle_http_request_duration_seconds`.
4. Inspect room lock and store read performance to determine if event fetch or notification dispatch is delayed.

## Mitigation
- Ensure server resources (CPU/memory) are not exhausted.
- Check storage read latency to ensure historical event retrieval is not stalling sync workers.
