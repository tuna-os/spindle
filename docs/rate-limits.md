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

There are three, and they all sit on the unauthenticated edge.

| Endpoint | Key | Limit | Counted when |
|---|---|---|---|
| `POST /login` (password) | account | 5 per 60 s | a failed attempt; a success forgets both keys' history |
| `POST /login` (password) | source address | 30 per 60 s | a failed attempt |
| `POST /register` | source address | 5 per 300 s | a request that carries `auth`, i.e. after the mandatory first 401 |

Both login keys are checked before the password is, so a caller over the
limit does not get an Argon2 verification out of each attempt. Both are
needed: per-account alone misses credential stuffing, per-source alone
locks out everyone behind one NAT. The reasoning is in the module header.

**Nothing an authenticated account does is rate limited.** Event sends,
room creation, invites, joins, media uploads, device registration, sync —
none of it. That is a choice this document records rather than defends:
the caps below bound what a single account can make the server *hold*,
and the benchmark rig depends on being able to issue requests as fast as
the server takes them. A per-account send rate is the obvious next limit
if abuse ever needs one, and it belongs in `[ratelimit]` beside `enabled`.

## Caps

| What | Cap | Configured by | Refusal |
|---|---|---|---|
| Media upload body | 50 MiB (`media::MAX_UPLOAD`) | fixed; advertised by `/media/config` | 413 `M_TOO_LARGE` |
| Filters held per user | 1,000 | `[limits] filters_per_user` | 400 `M_LIMIT_EXCEEDED` |
| Account-data types per user (global + per-room) | 20,000 | `[limits] account_data_per_user` | 400 `M_LIMIT_EXCEEDED`; rewriting an existing type is free |
| One-time keys held per device | 1,000 | `[limits] one_time_keys_per_device` | 400 `M_LIMIT_EXCEEDED`; counts held plus the batch offered |
| Pending delayed events per sender per room | 100 | `[delayed_events] max_per_room` | 400 `M_LIMIT_EXCEEDED` |
| Longest delay | 24 h | `[delayed_events] max_delay_ms` | 400, naming the limit |
| PDUs per federation transaction | 50 | fixed (the spec's own number) | 400 `M_BAD_JSON` |
| Federation transaction id length | 255 bytes | fixed | 400 `M_BAD_JSON`; the id is a replay key, and an unbounded key is a storage sink |
| Peer key-document validity | 7 days regardless of what the peer claims | `federation::MAX_KEY_VALIDITY` | refetch |

Every configurable cap refuses zero at startup. A zero would reject every
write, and a config that quietly disables a feature is worse than one that
will not load.

## Not bounded

Each of these grows with what an ordinary registered account chooses to
do, and nothing stops it. Listed with the shape a cap would take, so the
next one is a small change and not a design discussion.

| Growth | Driven by | Shape of a cap |
|---|---|---|
| Rooms created per user | `POST /createRoom` | per-user count, in `[limits]` |
| Aliases per room | `PUT /directory/room/{alias}` (members only since #291) | per-room count |
| Media objects, and bytes, per user | `POST /upload`, `POST /create` | per-user count and total bytes; the object-level cap exists, the account-level one does not |
| Devices per user | `POST /login` on a new device, `POST /register` | per-user count |
| Room tags per room per user | `PUT /tags/{tag}` | per-user-per-room count |
| Invites outstanding per sender | `POST /invite` | per-user count of pending invites |
| Events per room, and rooms joined per user | `PUT /send`, `POST /join` | a per-account send rate (above), not a cap: a room's history is the product |
| EDUs per federation transaction | `PUT /send/{txnId}` | a count beside the PDU cap; the spec allows 100 |
| Peer key fetches on a cache miss | any signed request from an unknown key id | per-origin refetch rate; filed as #288 |

The first four are the ones #268 named and #297 did not reach. None is
an attack that needs anything beyond a registered account. None is an
emergency either: every row above is storage growth at the rate one
account can generate it, on a server whose registration is rate limited
and can be closed.

## How to read this against the code

The inventory is hand-written, which is the failure mode this repository
usually refuses. The mitigation is that every row in the two bounded
tables names the constant or config field that enforces it, so a reader
can grep for it, and the `[limits]` and `[delayed_events]` fields are held
to `spindle.example.toml` by `scripts/config-drift.py`. A cap that lands
without a row here is not documented; a row here without a cap behind it
is a lie. Keep both columns honest.
