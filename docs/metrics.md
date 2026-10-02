# Metrics

Spindle shows its Prometheus metrics on a **separate listener**. The
listener is off until you configure it:

```toml
[metrics]
# Loopback on purpose. The exposition names the peers this server talks to
# and the volume it carries; it is an operator's surface, not a public one.
# Put a reverse proxy or your scraper's network in front of it deliberately.
bind = "127.0.0.1:9090"
```

Then send `GET /metrics` to `127.0.0.1:9090`. Without `bind`, there is
no listener and no port. This is the same opt-in shape as
`[auth.delegated]` and `[auth] builtin_oidc`.

## What is exported today

Each metric below is here because SPEC §17.2 names it and because a test
drives the operation and asserts the counter moved. A metric that no test
can show to move does not ship. On a dashboard, a gauge stuck at `0` looks
the same as a healthy system. The difference shows up during the incident
that the gauge had to explain.

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

- `deploy/prometheus/spindle-alerts.yaml`: the case-3 alert above, and the
  SPEC §18.3 latency targets as p50 and p99 alerts against `group`
  durability. It also alerts on a federation backlog that does not drain,
  sync lag, server errors, and loss of the listener. Thresholds come from
  the SPEC where it states one; the rest are initial values.
- `deploy/kubernetes/servicemonitor.yaml`: a headless Service that names the
  `metrics` port. It also holds a `ServiceMonitor` and a `PodMonitor` for the
  Prometheus Operator. Either one sets the `job="spindle"` label that the
  rules select on.
- `deploy/grafana/spindle.json`: one dashboard, with the targets first. It
  shows append p50/p99 by durability, the case-3 ratio, and HTTP rate and
  latency by route. It also shows the deepest federation destinations, sync
  subscribers and lag.

`scripts/check-observability-pack.py` runs in CI. It refuses a rule or a
panel that names a metric that this file or `metrics.rs` does not have.
This check makes sure that a rename leaves no rule that never fires.

## The one that matters

`spindle_fork_resolutions_total` is not a throughput metric. It is the
instrument that can falsify the architecture.

SPEC §9.2 splits every append into three cases, cheapest first:

- **case 1** — a non-state event. Cannot conflict; no state resolution.
- **case 2** — a state event whose key nothing in the fork window touched.
  One `apply()`; no state resolution.
- **case 3** — a state event contested inside the window. The expensive
  path: bounded state resolution.

SPEC §18.3 then states the target that makes the design testable, not
merely asserted:

> Case-3 fork resolutions as a fraction of federated events: **< 0.1%**

So the query that matters is the ratio, not the raw count:

```promql
rate(spindle_fork_resolutions_total{case="3"}[1h])
  / ignoring(case) rate(spindle_events_appended_total{origin="federated"}[1h])
```

If that stays under `0.001`, "no state resolution on the hot path" holds
for your traffic. If it climbs, the claim does not hold *for your
deployment*. That result is worth a report upstream. The whole point of a
falsifiable target in public is that someone can falsify it.

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
those and does not resolve them. `spindle-core` has bounded resolution
(#8, #30), but ingest does not call it yet (#16).

Spindle refuses a federated event that names the tips in conflict. A local
send sets the tip in conflict aside. The tip stays a forward extremity for
the resolver, and Spindle writes local events on the linear head without
it (#225). The server also logs a warning that names the room, the tip and
the key.

Spindle counts each fork once, when it sets the tip aside, not once per
send while the fork stays open. The counter sits at the decision point, so
it counts the same fork before and after #16 lands. Until #16 lands, a
non-zero case 3 means "Spindle found a contested fork and stepped around
it", not "a resolution ran".

## Checking the latency targets

SPEC §18.3 states local send at **p50 < 2 ms, p99 < 10 ms** against
`group` durability. `spindle_append_duration_seconds` measures exactly
that: the commit, not the whole request, because the target describes the
commit. Spindle weights the buckets to straddle those numbers (0.5 ms,
1 ms, 2 ms, 5 ms, 10 ms, …). It does not use the default set that most
libraries ship. That set starts at 5 ms, so it would put every one of
these appends in the first bucket and answer nothing.

```promql
histogram_quantile(0.99,
  rate(spindle_append_duration_seconds_bucket{durability="group"}[5m]))
```

The HTTP histogram answers the same question one layer out, per route.
`route` is the router's **matched path** — `/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}`,
never the path that the client requested. Thus the code bounds the label
set (101 routes today), not the room and user IDs that a caller happens to
use. A test asserts that no room ID appears in the exposition. Spindle
counts requests that match no route under a single `unmatched` label. So a
scanner that walks random URLs is not an unbounded source of series.

## Federation backlog and sync lag

These are two of the four things that dashboards must cover, per the exit
criteria of #19. The other two are durability (the `durability` label of
the append histogram) and unexpected fork paths, above.

The delivery loop sets `spindle_federation_queue_depth` from its own view
of the outbox. So the gauge cannot disagree with what the loop delivers.
The **twenty deepest destinations get their own series, and Spindle sums
the rest into `other`**. A room full of fabricated server names must not
be able to mint a series each and turn the scrape into the attack.
Spindle adds up the tail and never drops it.

```promql
topk(5, spindle_federation_queue_depth)
```

`spindle_sync_lag_seconds` needs its definition stated, because
"watermark lag" can mean several things. Here it is **the age of the
newest event that a `/sync` delivered**, measured at delivery. A client
that keeps up sees milliseconds; a server that falls behind sees this
climb. Spindle does not count syncs that deliver nothing. An empty sync is
a client that is up to date, not one that lags. A zero score for it would
flatten the average that matters.

## What is not here yet

Per #166: OpenTelemetry traces (slice 4).

SPEC §17.2 also names a **hit rate of the state-trie cache**. That metric
is absent, and the reason deserves a note. There is no state-node cache to
instrument. Spindle reads nodes from the store through the ordinary read
path.

To export a hit rate would mean to invent one. A metric that reports
on something that does not exist is worse than a missing metric. The rest
of this page runs on the same argument. The metric arrives when the cache
does.

Per-room series are deliberately absent and will stay that way. A server
with 10,000 rooms would mint tens of thousands of mostly-idle series. The
scrape cost would then grow with the room count, not with traffic. The
room endpoints of the [admin API](delegated-auth.md) answer per-room
questions, and they already have an authorization model. `/metrics`
answers "how is the server doing", with label sets bounded by config.
