# Runbook: SpindleAppendLatencyHigh

## Overview
- **Alert Names**: `SpindleAppendP99AboveTarget`, `SpindleAppendP50AboveTarget`
- **Severity**: `warning`
- **Metric**: `spindle_append_duration_seconds_bucket{durability="group"}`
- **Condition**: p99 > 10ms or p50 > 2ms over 5 minutes, sustained for 15 minutes.

## Context
SPEC §18.3 targets local send commit latencies of p50 < 2ms and p99 < 10ms for `group` durability. `spindle_append_duration_seconds` measures the exact storage commit phase (including I/O and fsync).

## Impact
- Higher append latency directly slows down event submission and increases HTTP response times for sending messages.

## Diagnostic Steps
1. Check disk I/O metrics and storage backend performance (fjall store disk write latency, IOPS, and fsync queue time).
2. Query PromQL for append duration quantiles by durability mode:
   ```promql
   histogram_quantile(0.99, sum by (le) (rate(spindle_append_duration_seconds_bucket[5m])))
   histogram_quantile(0.50, sum by (le) (rate(spindle_append_duration_seconds_bucket[5m])))
   ```
3. Check system resource utilization (disk throughput, CPU usage, memory pressure).

## Mitigation
- Verify storage device health and ensure adequate I/O throughput for disk flushes.
- Inspect room lock contention metrics (`spindle_room_lock_acquisitions_total`) to rule out concurrency bottlenecks.
