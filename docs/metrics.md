# Metrics

Spindle exposes Prometheus metrics on a **separate listener**, off unless
you configure it:

```toml
[metrics]
# Loopback on purpose. The exposition names the peers this server talks to
# and the volume it carries; it is an operator's surface, not a public one.
# Put a reverse proxy or your scraper's network in front of it deliberately.
bind = "127.0.0.1:9090"
```

Then `GET http://127.0.0.1:9090/metrics`. Absent `bind`, there is no
listener and no port — the same opt-in shape as `[auth.delegated]` and
`[auth] builtin_oidc`.

## What is exported today

Each metric below is here because SPEC §17.2 names it and because a test
drives the operation and asserts the counter moved. A metric that cannot
be shown to move does not ship: a gauge stuck at `0` is indistinguishable
on a dashboard from a healthy system, and the difference surfaces during
the incident it was supposed to explain.

| Metric | Type | Labels | What it tells you |
|---|---|---|---|
| `spindle_build_info` | gauge | `version` | Which build the dashboard is watching. Always `1`. |
| `spindle_events_appended_total` | counter | `origin` = `local`\|`federated` | Events that reached a room log. The denominator below. |
| `spindle_fork_resolutions_total` | counter | `case` = `1`\|`2`\|`3` | Which of SPEC §9.2's three cases carried each append. |

## The one that matters

`spindle_fork_resolutions_total` is not a throughput metric. It is the
instrument the architecture is falsified by.

SPEC §9.2 splits every append into three cases, cheapest first:

- **case 1** — a non-state event. Cannot conflict; no state resolution.
- **case 2** — a state event whose key nothing in the fork window touched.
  One `apply()`; no state resolution.
- **case 3** — a state event contested inside the window. The expensive
  path: bounded state resolution.

SPEC §18.3 then states the target that makes the design testable rather
than merely asserted:

> Case-3 fork resolutions as a fraction of federated events: **< 0.1%**

So the query that matters is the ratio, not the raw count:

```promql
rate(spindle_fork_resolutions_total{case="3"}[1h])
  / ignoring(case) rate(spindle_events_appended_total{origin="federated"}[1h])
```

If that stays under `0.001`, "no state resolution on the hot path" is
holding for your traffic. If it climbs, the claim is not holding *for
your deployment*, and that is a finding worth reporting upstream — the
whole point of publishing a falsifiable target is that someone can
falsify it.

An alert worth having:

```yaml
- alert: SpindleForkCase3Elevated
  expr: >
    rate(spindle_fork_resolutions_total{case="3"}[1h])
      / ignoring(case) rate(spindle_events_appended_total{origin="federated"}[1h])
      > 0.001
  for: 6h
  annotations:
    summary: Case-3 state resolutions above the SPEC §18.3 target
```

The six-hour window is deliberate: this is a design-health signal, not a
pager. A brief spike during a federation catch-up is expected.

### One caveat, stated plainly

Case 3 counts **appends that needed the resolver**. Today Spindle's ingest
path refuses those rather than resolving them: bounded resolution is
implemented in `spindle-core` (#8, #30) but is not yet wired into ingest
(#16). The counter sits at the decision point, so it counts the same
event before and after that lands — but until it does, a non-zero case 3
means "a contested state event arrived and was rejected", not "a
resolution ran".

## What is not here yet

Per #166, in order: append-latency and HTTP histograms (slice 2);
federation queue depth, state-trie cache hit rate, sync subscriber count
and watermark lag (slice 3); OpenTelemetry traces (slice 4).

Per-room series are deliberately absent and will stay that way. A server
with 10,000 rooms would mint tens of thousands of mostly-idle series, and
the scrape cost would grow with the room count rather than with traffic.
Per-room questions are answered by the [admin API](delegated-auth.md)'s
room endpoints, which already have an authorization model; `/metrics`
answers "how is the server doing", with label sets bounded by config.
