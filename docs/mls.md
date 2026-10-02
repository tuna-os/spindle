# MLS: the go/no-go review

**Decision on 2026-10-02: no-go.** Spindle does not start MLS work yet.
This page records the evidence, what the proposals ask of a server, and
the events that reopen the question. It is the design review that
[#23](https://github.com/tuna-os/spindle/issues/23) asks for. When a
trigger at the end of this page fires, update this page before you write
code.

## The gates

The exit criteria of #23 name four conditions. Only one passes today.

| Gate | Result | Evidence on 2026-10-02 |
|---|---|---|
| Megolm compatibility is complete | Pass | The M2 row of [docs/dashboard.md](dashboard.md) is **Done**: E2EE transport, fallback keys, device lists, key backup and cross-signing. |
| A stable specification | Fail | No MLS proposal has left review. The next table has the details. |
| A maintained client | Fail | No client that people use speaks any of the proposals. The second table has the details. |
| Hub mode is available | Fail | [#22](https://github.com/tuna-os/spindle/issues/22) (MSC3995) is open, and the M6 row of the dashboard says "Not started". |

### The proposals

| Proposal | State | Last change | Summary |
|---|---|---|---|
| [MSC4244](https://github.com/matrix-org/matrix-spec-proposals/pull/4244) | Draft, `[WIP]` | 2025-02-03 | Plain RFC 9420 MLS. One server per room, the room creator, is the MLS Delivery Service (DS). The DS orders commits. All other traffic uses the full mesh. Joins, leaves, kicks, bans and the transfer of the DS role are still `TODO`. It has no unstable prefix. |
| [MSC4256](https://github.com/matrix-org/matrix-spec-proposals/pull/4256) | Open, not a draft | 2026-09-29 | A new room version (`de.bwi.mls.v1` while unstable). The server sees almost no room state. A `federation.powers` list in each commit names the servers that can commit. The author says the next revision comes at the Matrix Conference. |
| [MSC4038](https://github.com/matrix-org/matrix-spec-proposals/pull/4038) | Draft | 2023-07-19 | Key backup for MLS. It targets the decentralised variant (MSC2883), not MSC4244 or MSC4256. |
| [MSC2883](https://github.com/matrix-org/matrix-spec-proposals/pull/2883) | Draft, `[WIP]` | 2026-06-02 | Decentralised MLS (DMLS). Commits can fork, so devices keep old keys at each fork. |
| [MSC4245](https://github.com/matrix-org/matrix-spec-proposals/pull/4245), [MSC4246](https://github.com/matrix-org/matrix-spec-proposals/pull/4246) | Open | 2025-02-18, 2024-12-21 | MSC4244 needs both. MSC4245 puts the encryption algorithm in the create event. MSC4246 lets a server send to-device messages. |

### The implementations

| Implementation | For | Last commit | Status |
|---|---|---|---|
| [synapse-mls](https://gitlab.opencode.de/bwi/bundesmessenger/mls/synapse-mls) | MSC4256, server | 2025-02-07 | A Synapse fork from BWI. No activity since the MSC opened. |
| [mls-test-client](https://gitlab.opencode.de/bwi/bundesmessenger/mls/mls-test-client) | MSC4256, client | 2025-02-13 | Its own description calls it a "simplistic demo client". |
| [matrix-dmls](https://gitlab.matrix.org/uhoreg/matrix-dmls) | MSC2883 | 2023-10-05 | Its README says "not ready for use". It pins a fork of OpenMLS. |
| matrix-rust-sdk, matrix-js-sdk | — | — | A code search for `mls`, `dmls` and `openmls` found no MLS code in either SDK. Element, Element X and the other clients in the README use these SDKs. |
| [OpenMLS](https://github.com/openmls/openmls) 0.9.0, [mls-rs](https://github.com/awslabs/mls-rs) 0.56.0 | RFC 9420 | August 2026 | Two maintained Rust MLS libraries. They are libraries, not Matrix clients, so they do not satisfy the client gate. They are the candidates for an interop test. |

## What the proposals ask of a server

This section compares each requirement in the #23 scope with what Spindle
serves today. It is the work list for a prototype. It is not a plan to
start one.

**Commit order.** MLS fails when two commits build on one epoch. Each
proposal answers this with one server that decides the order. In
MSC4244 that server is the DS. In MSC4256 it is the first entry of
`federation.powers`. The other servers in that list get five-minute turns,
and a commit from a server outside the list travels as an
`m.mls.pending_commit`.

Spindle already gives each room a total order: the linear index (`li`) of
SPEC §5. On one server, `li` order is commit order and the DS check is one
state lookup. Across servers, `li` is a total order only under hub mode,
so this requirement waits for #22.

**Epoch.** Neither proposal defines a state event that holds the epoch. In
MSC4256 the `m.mls.commit` state event is the current commit, and every
later event cites that commit in its `auth_events`. MSC4244 keeps the
epoch inside the MLS group state, which the server does not read. SPEC
§16.2 named an `m.room.mls_epoch` event. No proposal has that event, and
this change removes it from SPEC.

**Key packages.** Both proposals upload KeyPackages as one-time keys and
last-resort KeyPackages as fallback keys. The one-time key store in
`crates/spindle-server/src/devices.rs` does not check the algorithm. It
keeps the key value as opaque JSON, and a claim takes the first key that
has the requested `algorithm:` prefix.

The MSC4256 format puts the
ciphersuite in the algorithm name and sends a string value, so the store
accepts it without change. MSC4244 adds an `mls` object to `/keys/claim`,
which filters by ciphersuite and capabilities. Spindle ignores that
object, so it can return a KeyPackage that the client cannot use. MSC4256
also adds `GET /keys/list`, which Spindle does not serve.

**Welcome.** Both proposals send the Welcome message as a to-device
message. In MSC4256 a client sends it, and the per-device inbox carries it
today. A Welcome that holds the ratchet tree can be large, so the to-device
size cap needs a test with a real group. In MSC4244 the DS server sends
the commits and the Welcome itself (MSC4246). Spindle has no to-device
path that a server starts.

**Backup.** MSC4038 adds the `m.dmls_backup.v1.aes-hmac-sha2` algorithm
and uses the epoch and its creator as the session ID. The backup store in
`crates/spindle-server/src/backups.rs` keeps the algorithm and the session
data opaque, so a server change is unlikely. But the MSC4038 author
wrote it for DMLS. MSC4256 does not allow key backup at all. It asks for a
protocol that syncs history in its place.

**Recovery.** MSC4244 does not say what happens when the DS goes away. The
proposal lists that case as an open issue. MSC4256 lets a room keep old
private keys for `security.window` seconds, up to seven days, so that
clients can recover from two commits on one epoch. After that window, a
removed device needs a new Welcome, and messages from the conflict stay
unreadable. A test of these two cases on Spindle needs a client that
supports MLS.

## Spindle to Spindle, and DMLS

A maintainer comment on #23 names
[matrix-dmls](https://gitlab.matrix.org/uhoreg/matrix-dmls) as the start
point for federation with other Matrix servers. The comment adds that
Spindle to Spindle might not need DMLS. The table below shows why.

| Room shape | Can commits fork? | MLS variant |
|---|---|---|
| One Spindle server | No. `li` orders every commit. | RFC 9420, as is |
| Spindle servers under hub mode (#22) | No. The hub assigns `li` for the room. | RFC 9420, as is |
| Spindle with Synapse or other servers on the full mesh | Yes. The DAG lets two servers commit at one time. | DMLS (MSC2883), or a DS as in MSC4244 |

DMLS has a cost. MSC4244 and MSC4256 both state that DMLS gives less
forward secrecy, because a device must keep keys for each fork point. So DMLS
belongs only in the third row, and the first two rows must not pay for it.
Also, matrix-dmls depends on a forked OpenMLS from 2023. A prototype must
rebase that fork on a current OpenMLS release before Spindle can use it.

## What reopens the question

Check these events before each M6 milestone review. When one fires,
update the tables above with the new dates.

- MSC4256 gets the revision that its author announced, or MSC4244 leaves
  draft and fills its `TODO` sections.
- A client that people use ships an MLS mode, with commits in the last
  six months. A test client does not count.
- #22 hub mode reaches `main`.

When all three gates pass, the work follows #23 in order. First, put a
prototype behind the `unstable-msc4244` or `unstable-msc4256` Cargo
feature, off by default. Then add an interop test against a real client or
against OpenMLS. Megolm rooms and Megolm clients must see no change. No
MLS code turns on by default until the interop and recovery tests pass.
