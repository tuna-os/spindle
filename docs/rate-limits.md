# Rate limits and resource caps: what is bounded, and what is not

The #268 audit asked a question this repository had never answered in one
place: `[ratelimit]` exists and every test disables it, so *what is
actually limited?* This is the inventory. It is deliberately blunt about
the unbounded column, because a limit nobody has written down is a limit
nobody can tell is missing.

Two different things are bounded here, and they fail differently:

- **Rates** — how often a caller may do something. Enforced by
  `crates/spindle-server/src/ratelimit.rs`, a fixed-window counter keyed
  by account and by source address, in memory (single-node; a multi-node
  deployment is #24's problem). Refused with 429 `M_LIMIT_EXCEEDED` and a
  `retry_after_ms`.
- **Caps** — how much a caller may make this server hold or process at
  once. Enforced at the write, refused with 400 `M_LIMIT_EXCEEDED` (or the
  spec's own code where it has one), and never reset by waiting.

## Rates

There are two kinds. The fixed windows below guard the unauthenticated
edge and MatrixRTC (#38, #39). The per-account write budgets after them
(#741) limit the usual writes of an account.

| Endpoint | Key | Limit | Counted when |
|---|---|---|---|
| `POST /login` (password) | account | 5 per 60 s | a failed attempt; a success forgets both keys' history |
| `POST /login` (password) | source address | 30 per 60 s | a failed attempt |
| `POST /register` | source address | 5 per 300 s | a request that carries `auth`, i.e. after the mandatory first 401 |
| `PUT /send/m.rtc.notification` (and the MSC4075 unstable name) | account | `[ratelimit] rings_per_minute`, 10 | every attempt, delayed or not, whether or not the room then refuses it |
| `POST /user/{userId}/openid/request_token` | user | 20 per 60 s | every request, before the token is minted |
| `POST /_spindle/rtc/livekit/sfu/get` (built-in LiveKit service) | user | 20 per 60 s | every request that carried a live OpenID token, before the membership check |

The two mints are limited because they are not reads: an OpenID token is a
durable row written on the caller's say-so, and both tokens exist to make
a third party — a JWT service, an SFU — do work. Minting is an HMAC here
and a room on the SFU there, which is the asymmetry #38 names. A client
mints one of each per call it joins, so twenty a minute is a busy user
several times over and a loop within seconds.

Both login keys are checked before the password is, so a caller over the
limit does not get an Argon2 verification out of each attempt. Both are
needed: per-account alone misses credential stuffing, per-source alone
locks out everyone behind one NAT. The reasoning is in the module header.

### Per-account write budgets

Every room event, join, invite, room creation and upload spends from a
per-account token bucket: `burst` requests at once, refilled at
`per_second`. Each row is its own bucket, so an account that has spent its
sends can still join. Configured in `[ratelimit]`; the defaults are
Synapse 1.164's, so an operator's numbers and a client's backoff carry
across a migration in either direction.

| Endpoint | Key | Default | Synapse name | Counted when |
|---|---|---|---|---|
| `PUT /rooms/{id}/send/{type}/{txn}` (rings too), `PUT /rooms/{id}/state/...`, `PUT /rooms/{id}/redact/...` | account | `messages`: burst 10, 0.2/s | `rc_message` | every attempt, delayed or not, except a retried transaction ID, which is answered from what it recorded |
| `POST /join/{idOrAlias}`, `POST /rooms/{id}/join`, `POST /knock/{idOrAlias}`, answered here | account | `joins_local`: burst 10, 0.1/s | `rc_joins.local` | before the membership event is built |
| the same, carried to another server (`make_join`/`send_join`, `make_knock`/`send_knock`) | account | `joins_remote`: burst 10, 0.01/s | `rc_joins.remote` | before the handshake; a join that tries locally and finds no room spends both |
| `POST /rooms/{id}/invite` | inviter | `invites_per_issuer`: burst 10, 0.3/s | `rc_invites.per_issuer` | every attempt |
| `POST /rooms/{id}/invite`, and `PUT /_matrix/federation/v2/invite` from other servers | invitee | `invites_per_target`: burst 5, 0.003/s | `rc_invites.per_user` | every local attempt that passed the inviter's budget, and every federated invite for a local user, before this server co-signs it |
| `POST /createRoom` | account | `room_creation`: burst 10, 0.016/s | `rc_room_creation` | every attempt; the request's own `invite` list is not counted again |
| `POST /media/v3/upload`, `POST /media/v1/create` | account | `media_uploads`: burst 50, 10/s | `rc_media_create` | every attempt; filling a created ID (`PUT /media/v3/upload/{server}/{id}`) is not counted again |

The refusal is 429 `M_LIMIT_EXCEEDED`, with `retry_after_ms` and a
`Retry-After` header. Both give the time until the bucket has one more
request. A refusal spends nothing. Thus a client that tries again and
again does not make its own wait longer.

These limits are buckets, not windows like the login limits. A window
is correct against password attacks, where any steady rate is the
attack. For usual writes, a steady rate below the refill is the correct
use. The bucket must find the difference between a burst from a person
and a flood from a script. `ratelimit.rs` gives the full reason.

**Exempt** accounts follow Synapse and the appservice spec:

- The sender user of each appservice.
- The users in the namespaces of a registration with `rate_limited:
  false`. A registration without the key has limits, as the spec says.
- Server admins. Synapse does this per account with its override table.
  This server has no such table. An admin who removes spam must not get
  a refusal for too many sends.

The server reads the exemption only after a budget is empty. Thus the
usual path costs no account read.

**No budget** applies to these writes: device registration, profile
changes, `PUT /typing`, receipts, account data, to-device messages and
room upgrades. Sync and all other reads have no limit. That is a decision:
the benchmark rig measures reads, and the caps below limit what an
account can make the server *hold*.

## Caps

| What | Cap | Configured by | Refusal |
|---|---|---|---|
| Media upload body | 50 MiB by default | `[media] max_upload_bytes`; advertised by `/media/config` | 413 `M_TOO_LARGE` |
| Media bytes held per account | none by default | `[media] max_bytes_per_user` | 403 `M_RESOURCE_LIMIT_EXCEEDED`, with `admin_contact` from `[server.support]` when set; checked before any byte is stored; deleting media gives its bytes back; appservice users and admins exempt as from the write budgets |
| Filters held per user | 1,000 | `[limits] filters_per_user` | 400 `M_LIMIT_EXCEEDED` |
| Account-data types per user (global + per-room) | 20,000 | `[limits] account_data_per_user` | 400 `M_LIMIT_EXCEEDED`; rewriting an existing type is free |
| One-time keys held per device | 1,000 | `[limits] one_time_keys_per_device` | 400 `M_LIMIT_EXCEEDED`; counts held plus the batch offered |
| Pushers registered per user | 100 | `[limits] pushers_per_user` | 400 `M_LIMIT_EXCEEDED`; replacing a registration is free |
| Pending delayed events per sender per room | 100 | `[delayed_events] max_per_room` | 400 `M_LIMIT_EXCEEDED` |
| Longest delay | 24 h | `[delayed_events] max_delay_ms` | 400, naming the limit |
| Rate-limit counter keys | 65,536 windows and 65,536 write buckets; identifiers at most 512 bytes | `ratelimit::MAX_TRACKED_KEYS`, `MAX_KEY_BYTES` | new identifiers refused at saturation; expired windows and refilled buckets reclaimed without resetting live budgets |
| Peer-key fetches | 32 concurrent direct fetches; 8,192 entries in each direct-fetch cache | `federation::MAX_CONCURRENT_KEY_FETCHES`, `MAX_KEY_FETCH_ORIGINS` | excess direct fetches refused; failures retained for 60 s and successful refetches throttled for 10 s |
| Incoming EDUs processed per transaction | 100 | `inbound::send` | additional EDUs ignored; entire transaction body limited to 1 MiB |
| Pending delayed events per sender across rooms | 1,000 | `[delayed_events] max_per_user` | 400 `M_LIMIT_EXCEEDED` |
| PDUs per federation transaction | 50 | fixed (the spec's own number) | 400 `M_BAD_JSON` |
| Federation transaction id length | 255 bytes | fixed | 400 `M_BAD_JSON`; the id is a replay key, and an unbounded key is a storage sink |
| Peer key-document validity | 7 days regardless of what the peer claims | `federation::MAX_KEY_VALIDITY` | refetch |
| Ephemeral EDUs (typing, presence) waiting per federation destination | 100 | `Federation::queue_edu` | oldest dropped; held in memory only, and dropped with a transaction that fails |
| Readers' receipts waiting per federation destination | 1,000 | `federation::MAX_PENDING_RECEIPTS` | a new reader's receipt is not queued; a waiting reader's is replaced |
| Durable EDUs (to-device, device-list, cross-signing) per outbound transaction | 50 of the spec's 100 | `federation::edu_outbox::PER_TRANSACTION` | the rest wait, in order, for the next transaction; ephemeral EDUs fill the remaining slots |
| Push notifications waiting per gateway URL | 10,000 | `push::QUEUE_CAP` | oldest dropped, with its stored row; each is stored until its gateway answers, so a restart resumes them |

Every configurable cap refuses zero at startup. A zero would reject every
write, and a config that quietly disables a feature is worse than one that
will not load.

## Account-driven storage growth

Each of these grows with what an ordinary registered account chooses to
do, and no cap stops it; the write budgets above bound how fast, not how
far. Listed with the shape a cap would take, so the next one is a small
change and not a design discussion.

| Growth | Driven by | Shape of a cap |
|---|---|---|
| Rooms created per user | `POST /createRoom` (budgeted: `room_creation`) | per-user count, in `[limits]` |
| Aliases per room | `PUT /directory/room/{alias}` (members only since #291) | per-room count |
| Media objects per user | `POST /upload`, `POST /create` (budgeted: `media_uploads`) | per-user count; total bytes are capped by `[media] max_bytes_per_user` when it is set |
| Devices per user | `POST /login` on a new device, `POST /register` | per-user count |
| Room tags per room per user | `PUT /tags/{tag}` | per-user-per-room count |
| Invites outstanding per sender | `POST /invite` (budgeted: `invites_per_issuer`) | per-user count of pending invites |
| Events per room, and rooms joined per user | `PUT /send`, `POST /join` (budgeted: `messages`, `joins_local`, `joins_remote`) | none: a room's history is the product, and the budgets are the bound |
| To-device messages, device-list and cross-signing updates owed to an unreachable server | `PUT /sendToDevice` to its users; key changes while sharing a room with it | per-destination count. Like the PDU outbox, these rows (`Keyspace::EduOutbox`) are kept until the peer acknowledges them, because dropping one is an undecryptable message later (#739) |



The first four are the ones #268 named and #297 did not reach. None is
an attack that needs anything beyond a registered account. None is an
emergency either: every row above is storage growth at the rate one
account can generate it, on a server whose registration is rate limited
and can be closed.

For v0.1, close registration and bound ingress.
Set a process memory ceiling and monitor storage quotas. See
[operations.md](operations.md). The media quota is the one per-account
storage bound Spindle supplies, and it is off unless configured; the rest
are operator-enforced.

## How to read this against the code

The inventory is hand-written, which is the failure mode this repository
usually refuses. The mitigation is that every row in the two bounded
tables names the constant or config field that enforces it, so a reader
can grep for it, and the `[limits]`, `[delayed_events]`, `[media]` and
`[ratelimit]` fields are held
to `spindle.example.toml` by `scripts/config-drift.py`. A cap that lands
without a row here is not documented; a row here without a cap behind it
is a lie. Keep both columns honest.
