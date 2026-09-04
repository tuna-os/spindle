# Runbook: SpindleServerErrors

## Overview
- **Alert Name**: `SpindleServerErrors`
- **Severity**: `warning`
- **Metric**: `spindle_http_requests_total{status=~"5.."}` / `spindle_http_requests_total`
- **Condition**: HTTP 5xx error rate > 1% (0.01) over 5 minutes, sustained for 10 minutes.

## Context
Measures the proportion of HTTP requests resulting in internal server errors (5xx status codes).

## Impact
- Failures for client API calls or inbound federation endpoints.

## Diagnostic Steps
1. Identify affected routes and methods in Prometheus:
   ```promql
   sum by (route, method, status) (rate(spindle_http_requests_total{status=~"5.."}[5m]))
   ```
2. Search server logs for 500 error stack traces and internal panic messages.
3. Check database/store write permissions and storage state.

## Mitigation
- Address root cause identified in application error logs (e.g. database locks, unhandled error conditions).
