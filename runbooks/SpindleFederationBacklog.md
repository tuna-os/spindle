# Runbook: SpindleFederationBacklog

## Overview
- **Alert Name**: `SpindleFederationBacklog`
- **Severity**: `warning`
- **Metric**: `spindle_federation_queue_depth`
- **Condition**: Outbound federation queue > 500 events for destination (excluding `other`), sustained for 30 minutes.

## Context
Spindle tracks outbound federation event delivery queues per destination server. A growing backlog indicates outbound transactions are failing, timing out, or being rate-limited by the target remote Matrix homeserver.

## Impact
- Delivery delays to remote Matrix homeservers; users on target homeservers will receive events late.

## Diagnostic Steps
1. Identify the affected destination server from the `destination` label.
2. Check network connectivity and DNS resolution for the remote server domain.
3. Inspect Spindle server federation logs for outbound connection errors, TLS handshakes, or HTTP response errors (e.g. 502, 504, 429) from the target peer.

## Mitigation
- If the remote server is down, wait for remote recovery; queue depth will drain once connectivity is restored.
- If the remote server is unreachable due to routing/DNS issues, resolve host connectivity.
