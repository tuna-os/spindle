# Runbook: SpindleForkCase3Elevated

## Overview
- **Alert Name**: `SpindleForkCase3Elevated`
- **Severity**: `info`
- **Metric**: `spindle_fork_resolutions_total{case="3"}` / `spindle_events_appended_total{origin="federated"}`
- **Condition**: Ratio > `0.001` (0.1%) over a 1-hour rate, sustained for 6 hours.

## Context
SPEC §18.3 establishes that Case-3 fork resolutions (contested state events within the fork window) should constitute less than 0.1% of federated events. A rise above this threshold indicates that state resolution is running on the append path more frequently than expected, or that inbound federated events with state conflicts are being rejected/resolved at an elevated rate.

## Impact
- Elevated Case-3 occurrences increase CPU overhead per append.
- Currently, Spindle's ingest path rejects Case-3 appends pending full wiring of state resolution (#16). Thus, elevated Case-3 rate indicates incoming federated events are being rejected.

## Diagnostic Steps
1. Verify the current ratio using Prometheus:
   ```promql
   rate(spindle_fork_resolutions_total{case="3"}[1h]) / ignoring(case) rate(spindle_events_appended_total{origin="federated"}[1h])
   ```
2. Check logs for incoming federation state conflict errors or event rejections.
3. Identify participating federated servers and room IDs experiencing high branch creation / concurrent state updates.

## Mitigation
- If a specific remote server is generating high volumes of conflicting state events, inspect room state and federation status.
- Monitor overall server performance and CPU consumption.
- Report persistent high Case-3 ratios upstream with trace data as a benchmark finding.
