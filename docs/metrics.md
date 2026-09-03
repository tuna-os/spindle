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
| `spindle_append_duration_seconds` | histogram | `durability` | Time to commit one event, timed around the commit itself. |
| `spindle_http_requests_total` | counter | `route`, `method`, `status` | Requests served. |
| `spindle_http_request_duration_seconds` | histogram | `route` | Time to serve one request. |
| `spindle_federation_queue_depth` | gauge | `destination` | Events waiting to go out, per peer. |
| `spindle_sync_subscribers` | gauge | — | Clients currently blocked in a long-polling `/sync`. |
| `spindle_sync_lag_seconds` | histogram | — | Age of the newest event a `/sync` delivered. |
| `spindle_room_registry_acquisitions_total` | counter | `mode` = `exclusive`\|`shared` | Acquisitions of the registry that hands rooms out. |
| `spindle_room_lock_acquisitions_total` | counter | `mode` = `exclusive`\|`shared` | Acquisitions of a room's own lock: `exclusive` is the write path. |

## Alert rules, a scrape target and a dashboard

`deploy/` carries the pieces an operator would otherwise write from this
page (#325):

- `deploy/prometheus/spindle-alerts.yaml`: the case-3 alert above, the
  SPEC §18.3 latency targets as p50 and p99 alerts against `group`
  durability, a federation backlog that is not draining, sync lag, server
  errors, and the listener going away. Thresholds from the SPEC where it
  states one; the rest are starting points.
- `deploy/kubernetes/servicemonitor.yaml`: a headless Service naming the
  `metrics` port, and a `ServiceMonitor` and a `PodMonitor` for the
  Prometheus Operator, either of which sets the `job="spindle"` label the
  rules select on.
- `deploy/grafana/spindle.json`: one dashboard, the targets first: append
  p50/p99 by durability, the case-3 ratio, HTTP rate and latency by route,
  the deepest federation destinations, sync subscribers and lag.

`scripts/check-observability-pack.py` runs in CI and refuses a rule or a
panel that names a metric this file or `metrics.rs` does not have, so a
renamed metric cannot leave a rule that never fires.

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

Case 3 counts **forks that needed the resolver**. Today Spindle defers
those rather than resolving them: bounded resolution is implemented in
`spindle-core` (#8, #30) but is not yet wired into ingest (#16). A
federated event naming the contesting tips is refused. A local send sets
the contesting tip aside — it stays a forward extremity for the resolver,
and local events are authored on the linear head without it (#225) — and
the server logs a warning naming the room, the tip and the key. Each fork
is counted once, when the tip is set aside, not once per send while it
stays open. The counter sits at the decision point, so it counts the same
fork before and after #16 lands — but until it does, a non-zero case 3
means "a contested fork was found and stepped around", not "a resolution
ran".

## Checking the latency targets

SPEC §18.3 states local send at **p50 < 2 ms, p99 < 10 ms** against
`group` durability, which is what `spindle_append_duration_seconds`
measures — the commit, not the whole request, because that is what the
target describes. Buckets are weighted to straddle those numbers
(0.5 ms, 1 ms, 2 ms, 5 ms, 10 ms, …) rather than using the default set
most libraries ship, which starts at 5 ms and would put every one of
these appends in the first bucket and answer nothing.

```promql
histogram_quantile(0.99,
  rate(spindle_append_duration_seconds_bucket{durability="group"}[5m]))
```

The HTTP histogram answers the same question one layer out, per route.
`route` is the router's **matched path** — `/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}`,
never the path that was requested. That is what keeps the label set
bounded by the code (101 routes today) rather than by the room and user
IDs a caller happens to use; a test asserts that a room ID appears
nowhere in the exposition. Requests that match no route are counted
under a single `unmatched` label, so a scanner walking random URLs is
not an unbounded source of series.

## Federation backlog and sync lag

These are two of the four things #19's exit criteria say dashboards must
cover (the other two being durability — the append histogram's
`durability` label — and unexpected fork paths, above).

`spindle_federation_queue_depth` is set from the delivery loop's own
view of the outbox, so it cannot disagree with what is actually being
delivered. The **twenty deepest destinations get their own series and
the rest are summed into `other`**: a room full of fabricated server
names must not be able to mint a series each and turn the scrape into
the attack. The tail is added up, never dropped.

```promql
topk(5, spindle_federation_queue_depth)
```

`spindle_sync_lag_seconds` needs its definition stated, because
"watermark lag" can mean several things. Here it is **the age of the
newest event a `/sync` actually delivered**, measured at delivery. A
client keeping up sees milliseconds; a server falling behind sees this
climb. Syncs that deliver nothing are not counted — an empty sync is a
client that is up to date, not a lagging one, and scoring it zero would
flatten the average that matters.

## What is not here yet

Per #166: OpenTelemetry traces (slice 4).

**State-trie cache hit rate**, which SPEC §17.2 also names, is absent for
a reason worth writing down: there is no state-node cache to instrument.
Nodes are read from the store through the ordinary read path. Exporting
a hit rate would mean inventing one, and a metric that reports on
something that does not exist is worse than a missing metric — the same
argument the rest of this page runs on. It arrives when the cache does.

Per-room series are deliberately absent and will stay that way. A server
with 10,000 rooms would mint tens of thousands of mostly-idle series, and
the scrape cost would grow with the room count rather than with traffic.
Per-room questions are answered by the [admin API](delegated-auth.md)'s
room endpoints, which already have an authorization model; `/metrics`
answers "how is the server doing", with label sets bounded by config.
