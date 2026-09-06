# Spindle Alert Runbooks

This directory contains operational runbooks for alert rules defined in `deploy/prometheus/spindle-alerts.yaml`.

## Alerts Overview

| Alert Name | Severity | Description | Runbook |
|---|---|---|---|
| `SpindleForkCase3Elevated` | info | Case 3 state resolutions exceed SPEC §18.3 target (<0.1%) | [SpindleForkCase3Elevated.md](SpindleForkCase3Elevated.md) |
| `SpindleAppendP99AboveTarget` | warning | p99 commit duration under group durability > 10ms | [SpindleAppendLatencyHigh.md](SpindleAppendLatencyHigh.md) |
| `SpindleAppendP50AboveTarget` | warning | p50 commit duration under group durability > 2ms | [SpindleAppendLatencyHigh.md](SpindleAppendLatencyHigh.md) |
| `SpindleFederationBacklog` | warning | Federation outbox queue > 500 events for 30m | [SpindleFederationBacklog.md](SpindleFederationBacklog.md) |
| `SpindleSyncLagHigh` | warning | p99 sync delivery lag > 30s | [SpindleSyncLagHigh.md](SpindleSyncLagHigh.md) |
| `SpindleDown` | critical | Metrics listener unresponsive for 5m | [SpindleDown.md](SpindleDown.md) |
| `SpindleServerErrors` | warning | HTTP 5xx error rate > 1% over 5m | [SpindleServerErrors.md](SpindleServerErrors.md) |
