# Incident Template — Spindle

Use this template to document and coordinate response to incidents affecting Spindle deployments or operations. Link to this issue from the applicable postmortem if an incident review is warranted.

## Incident information

- **Date/time started:** (UTC)
- **Date/time resolved:** (UTC)
- **Severity:** (SEV1 / SEV2 / SEV3 / SEV4)
- **Component(s):** (e.g., sync, federation, state resolution, storage, metrics, replication)
- **Alert(s) triggered:** (link to matching runbook if applicable)
- **Affected users/rooms/servers:** (number and characteristics)

## Summary

<!-- One-paragraph summary of what happened. State the user-facing impact: what changed, what stopped working, or what became incorrect. Be specific about symptoms (sync latency, federation backlog, missing events, etc.). -->

## Root cause

<!-- Measured cause, not a hypothesis. Reference specific logs, error messages, or traces. Distinguish between the immediate technical cause and the systemic factor that enabled it. If not yet known, say so. Do not speculate. -->

## Timeline

<!-- Start from the earliest sign of the problem. Use UTC times. Include:
- When the problem first appeared (measured, not estimated)
- When it was detected (alert fired, user report, monitoring)
- Key actions taken
- When the impact ended
- When the fix was applied (if different)

Format: HH:MM UTC — observed or action -->

## Impact

- **Duration:** (total time users were affected)
- **Scope:** (number of affected users, rooms, federated servers; Matrix-specific: was it homeserver-wide or scoped?)
- **What failed or changed:** (be specific: sync halted, federation backlog grew, events lost, state resolution broken, metrics missing, etc.)

## Resolution

<!-- What was done to stop the ongoing impact. If automated, describe the automation. If manual, describe the steps and who performed them. Reference alert runbooks from `runbooks/` if applicable. -->

## Follow-up

- [ ] Postmortem scheduled (if SEV1/2, or if root cause analysis is incomplete)
- [ ] Tracking issue created: (link)
- [ ] Monitoring/alerting added or adjusted to prevent recurrence
- [ ] Related issues or PRs filed
- [ ] Prometheus alert rule updated if thresholds need tuning

## Notes

<!-- Anything else relevant: federation partner behavior, client compatibility, storage backend issues, concurrency patterns, etc. -->
