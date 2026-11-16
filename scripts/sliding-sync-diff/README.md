# Sliding sync differential harness

This harness sends the same Element X traffic to Spindle and to Synapse.
Then it compares the two servers' answers. Element X uses only
[MSC4186](https://github.com/matrix-org/matrix-spec-proposals/pull/4186)
sync, at `POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync`.
Synapse has its own MSC4186 code. Its answers are the reference.
The report shows each difference that a client can see.

## Run it

One command starts both servers, runs the scenario and stops the servers:

```sh
scripts/sliding-sync-diff/run.sh
```

The command builds Spindle from this checkout. To test a release image or a
binary, give `--spindle`:

```sh
scripts/sliding-sync-diff/run.sh --spindle image:ghcr.io/tuna-os/spindle:v0.1.0
scripts/sliding-sync-diff/run.sh --spindle binary:target/release/spindle
```

The command needs Python 3, `curl`, and Docker or Podman. The Python code
uses only the standard library. The run takes about two minutes.

| Option | Effect |
|---|---|
| `--keep` | The servers stay up after the run. |
| `--no-restart` | The run skips the `server-restart` step. |
| `-- ARGS` | `run.sh` gives `ARGS` to `sliding_sync_diff.py run`. |

Useful `ARGS`:

| Argument | Effect |
|---|---|
| `--batch 20` | A smaller growing batch than Element X (100). The range grows in more steps. |
| `--steps rename leave` | The run does only these steps after `initial`. |
| `--long-poll-ms 3000` | The timeout of each long poll. |
| `--json` | The report is JSON, not Markdown. |
| `--out DIR` | The run writes its files to `DIR`. |

## What the run writes

The run writes to `tmp/sliding-sync-diff/out/`:

| File | Contents |
|---|---|
| `report.md` | The report. The run also prints it. |
| `report.json` | The same report as JSON. |
| `synapse.jsonl`, `spindle.jsonl` | Each exchange in the sync-tap format, plus `step` and `phase`. |
| `synapse.names.json`, `spindle.names.json` | The map from room and event IDs to scenario names. |

`scripts/sync-tap/sync_tap_report.py` reads the `.jsonl` files without
change. Four small tools show the raw data:

```sh
scripts/sliding-sync-diff/show_step.py rename        # each exchange of one step
scripts/sliding-sync-diff/show_room.py g03           # one room in each answer
scripts/sliding-sync-diff/show_ext.py typing         # one extension in each answer
scripts/sliding-sync-diff/count_ext.py               # the answers that carry each extension
scripts/sliding-sync-diff/sliding_sync_diff.py report tmp/sliding-sync-diff/out
```

The last command compares the saved exchanges again. Use it after a
change to the comparison code.

## The servers

`up.sh` starts the two servers on loopback. It does not use TLS or
federation. Both servers use the server name `diff.test`, so a user ID is
the same string on each side.

| Server | Source | Port |
|---|---|---|
| Synapse | `docker.io/matrixdotorg/synapse:v1.164.2`, SQLite | 18008 |
| Spindle | This checkout, an image, or a binary | 18009 |

The containers use the host network. Rootless Podman can then run them
without `slirp4netns` or `pasta`. Each server registers users with its
shared secret. The script turns off the rate limits on both servers.
It also turns off presence in Synapse, because Element X does not ask for
the presence extension.

## The scenario

Alice is the Element X user. Her device is `ELEMENTX`. Six other users
change her room list. A seventh user (`henry`) shares no room with her at
the start. The seed gives Alice about 50 rooms:

* DMs, with `m.direct` account data. Alice has an open invite to one DM.
* Group rooms with names, topics and avatars, and group rooms without
  names. One room has only a canonical alias.
* A space with three child rooms.
* Encrypted rooms. The messages in them are `m.room.encrypted` shells.
* Open invites, a room that Alice left, and tags.
* A last message in each room, in a random order. The harness always uses the same
  seed. Thus recency is not creation order.

Then the steps change the rooms. After each change, the client syncs.

The steps are a new message, a rename, a mention, an accepted invite and a
rejected invite. Then come typing and receipts, account data, a new DM, a
leave, a join and a kick. Also a stranger joins an encrypted room, and
the topic and avatar change. Then the client gets an encrypted message, a
to-device message and a device key change. Alice opens rooms, a burst of
messages arrives, and a room upgrade occurs.

Some steps copy what Element X does to its connection:

| Step | What the client does |
|---|---|
| `pos-retry` | It loses the answer to one request. Then it sends the request again with the same `pos`. |
| `concurrent-cancel` | It leaves a long poll on the server. It sends a new request with the same `pos` before the first one ends. |
| `recover` | The app comes back from the background. The list goes back to `0..19` with the old `pos`, and then it grows again. |
| `restart` | The app starts with no `pos`. This occurs after `M_UNKNOWN_POS`. |
| `server-restart` | Both servers restart. The client continues with its `pos`. |

## The Element X requests

`ssdiff/elementx.py` builds the requests in the same way as
matrix-rust-sdk. The file names its sources in that repository.

* The `room-list` connection has one list, `all_rooms`. Its
  `required_state` is the SDK's list, with `timeline_limit: 1` and the
  filter `{}`. The extensions are `account_data`, `receipts` (all rooms) and
  `typing`.
* The first request asks for `0..19` with a timeout of 0. Then the range
  grows in batches of 100, with a timeout of 0. When the range holds the
  full list, the client long-polls.
* A room subscription adds `m.room.pinned_events` and uses
  `timeline_limit: 20`.
* The `encryption` connection has no lists. It enables `to_device`
  (with `since`) and `e2ee`.

The SDK does not send `include_heroes`. The request type in ruma has no
such field, so the harness does not send it.

## Replay a sync-tap recording

Replay mode takes the request bodies from a sync-tap file. It sends
them to both servers in the recorded order:

```sh
scripts/sliding-sync-diff/up.sh
python3 scripts/sliding-sync-diff/sliding_sync_diff.py replay tap.jsonl --mutate-every 10
scripts/sliding-sync-diff/up.sh --down
```

* The harness seeds the scenario first, because production room IDs do
  not exist on the test servers.
* Each server gets its own `pos` and its own to_device `since`. The
  harness never sends a recorded value.
* A recorded request with no `pos` starts that connection again.
* The harness maps the room IDs in `room_subscriptions` to scenario rooms,
  in the order it sees them.
* `--max-timeout-ms` (default 500) sets the maximum long-poll timeout.
  Recorded long polls of 30 seconds thus do not stop the replay.
* `--mutate-every N` applies the next scenario change after each `N`
  requests. Without it, the rooms do not change.
* `--user` keeps one recorded user. `--limit` keeps the first requests.

## How the comparison works

The harness names rooms by the scenario: `!g03`, not a room ID. It names
events by their body or their ciphertext. It removes these fields: `pos`,
`origin_server_ts`, `age`, `unsigned`, `event_id`, `prev_batch`,
`next_batch` and `txn_id`. It compares `bump_stamp` only as a sort order.

A step is all the answers one connection gets for one change. One server
can send a change in one answer, and the other server in two. Element X
sees no difference there, so the harness merges the answers of a step
before it compares them.

The report has these parts:

| Part | What it compares |
|---|---|
| Anomalies | The checks of `sync_tap_report.py`, on each server. An anomaly on Spindle only is the main result. |
| Room list differences | A model of the room list for each server: the rooms, the order, the names, the unread counts, the last event and the membership. |
| Client-visible differences | The list `count`, the rooms in the first window, and errors. |
| Wire-only differences | Each room field: `initial`, `name`, `heroes`, `required_state` types and keys, `timeline`, `limited`, `num_live`, the counts, `is_dm`, `invite_state`. Also each extension. |
| Explained differences | Known differences that are not Spindle bugs. Each one has a reason. |
| Long-poll timings | The time of each long poll. The change occurs before the request, so a long poll with news must return at once. |

### The anomaly checks

`scripts/sync-tap/sync_tap_report.py` holds the checks. The harness and
the production tap use the same code.

| Check | What Element X shows |
|---|---|
| `error` | An error answer. For `M_UNKNOWN_POS` the client starts again. |
| `count-drop` | The list `count` fell by more than a third, or to 0. |
| `count-silent` | The `count` fell, but no answer told the client that it left a room. The client keeps the room. |
| `room-lost` | The server sent a held room as `initial` again. The client discards the room's timeline. An accepted invite is not an anomaly. |
| `bump-backwards` | The `bump_stamp` of a room went down. |
| `bump-non-proper` | The `bump_stamp` went up, but the full timeline has no event type that MSC4186 lets bump a room. |
| `nameless` | An `initial` room has no name, no heroes and no name state. The list shows "Empty Room". |
| `hero-shape` | A hero has a key that MSC4186 does not define. ruma reads only `user_id`, `displayname` and `avatar_url`. |
| `empty-limited` | `limited: true` with no timeline. |
| `pos-chain` | A request `pos` is not the `pos` of the last answer. |
| `window-short` | An initial answer has fewer rooms than the ranges and `count` allow. |
| `slow` | An answer took 5 seconds more than its timeout. |

### The room list model

`ssdiff/model.py` follows the logic of matrix-rust-sdk. It does not run
the SDK. The model is the same for both servers. Its limits:

* The model sorts by `bump_stamp`. Current matrix-rust-sdk sorts by the
  latest event that the client computes, and uses `bump_stamp` only when
  no latest event exists. Older Element X builds sort by `bump_stamp`
  alone.
* The model names a hero from `displayname`, or else from the hero's
  member event, if the client has it. Otherwise the model skips the hero.
  The SDK does the same.
* The model does not calculate unread counts from receipts. Synapse sends
  `notification_count: 0` at all times, so the report explains those
  differences.

## Limits

* The connections run one after the other in each step. Element X runs
  `room-list` and `encryption` at the same time.
* After a change, each server gets a long poll with a 3 second timeout.
  Then each server gets polls with a timeout of 500 ms, until an answer
  has no news. Element X uses 30 seconds for each poll.
* The encrypted events are shells, and the device keys have no valid
  signatures. The servers do not examine them.
* The harness does not test federation, media or MSC4186 list filters.
  Element X sends no filter.
* The harness does not pin the Spindle release image. Give the tag or
  digest with `--spindle image:REF`.
