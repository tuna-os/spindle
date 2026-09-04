# Runbook: SpindleDown

## Overview
- **Alert Name**: `SpindleDown`
- **Severity**: `critical`
- **Metric**: `up{job="spindle"}`
- **Condition**: `up == 0` for 5 minutes.

## Context
Prometheus failed to scrape the Spindle metrics endpoint (`GET /metrics`) for 5 minutes.

## Impact
- Telemetry and operational monitoring for Spindle are offline.
- If the entire Spindle process crashed, client and federation traffic is unserved.

## Diagnostic Steps
1. Check if the Spindle process is running on the host/container.
2. Check metrics endpoint responsiveness directly:
   ```bash
   curl -I http://127.0.0.1:9090/metrics
   ```
3. Inspect Spindle stderr/stdout system logs for panics, OOM kills, or crash tracebacks.

## Mitigation
- If the process crashed, restart the Spindle service.
- If the process is alive but metrics port is unresponsive, verify network binding configuration in `spindle.toml` under `[metrics]`.
