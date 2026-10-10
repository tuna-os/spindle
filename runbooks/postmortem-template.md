# Postmortem Template — Spindle

Use this template to conduct a structured review of incidents affecting Spindle. The goal is to understand what happened, why, and how to prevent recurrence. Postmortems are blameless: they focus on systemic factors and process, not individual actions.

Reference the related incident issue for details on timeline, impact, and resolution.

## Postmortem information

- **Incident issue:** (link)
- **Date conducted:** (UTC)
- **Attendees:** (list of participants)
- **Facilitator:** (who led the review)
- **Postmortem lead:** (primary author)

## Incident summary

<!-- One paragraph. Link to the incident issue for full details. State what happened and the user-facing impact. -->

## Root cause analysis

### Primary cause

<!-- What was the direct technical cause? Be specific and evidence-based. For distributed systems, distinguish between local failure and failure due to peer behavior or network conditions. -->

### Contributing factors

<!-- Systemic or process factors that enabled or worsened the incident. Examples:
- Monitoring gap (alert threshold set too high, alert not configured, metric missing)
- Load testing gap (scenario not tested, edge case not covered)
- Deployment gap (configuration drift, unsafe rollout procedure)
- Dependency gap (Matrix spec change, federation partner behavior, storage backend issue)
- Concurrency gap (race condition, deadlock, or ordering assumption)
- State resolution gap (fork case not handled, Case 3 recurrence)
-->

## Timeline

<!-- Detailed timeline from incident issue, with added context on decisions and their rationale. -->

## Impact review

- **Duration:** (how long users were affected)
- **Scope:** (number of affected users, rooms, or federated servers)
- **Detectability:** (how was it discovered, could it have been detected sooner by metrics or alerts)

## Lessons learned

### What went well

<!-- Actions or safeguards that contained or mitigated the incident. -->

### What could be improved

<!-- Process, tooling, monitoring, testing, or deployment changes that would prevent or reduce the impact of a similar incident. -->

## Action items

<!-- Specific, measurable steps to address root causes and contributing factors. Each item should:
- State the problem being solved
- Propose a specific solution
- Assign an owner (or "unassigned")
- Estimate effort (small / medium / large)
- Set a target date for completion

Example:
- [small, 2026-11-01] Add Prometheus alert for storage backend contention. (tuna-os/spindle#NNN)
- [medium, 2026-11-15] Add integration test for federated room join race condition. (tuna-os/spindle#NNN)
-->

## Sign-off

- **Reviewed by:** (stakeholder, maintainer, or operations)
- **Date:** (UTC)

## Related resources

- [Incident template](incident-template.md)
- [Alert runbooks](README.md)
- Related issue(s): (links)
- Matrix Spec references: (relevant sections if applicable)
