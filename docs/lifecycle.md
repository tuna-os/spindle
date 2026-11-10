# Running a Spindle over time

The commands an operator uses between installing a server and retiring one:
backing it up, restoring it, checking its media, and moving its store forward
when the on-disk format changes. Part of #20.

Every one of these opens the store directly, and fjall holds an exclusive
lock, so **they run with the server stopped**. For a restore that is not just
a limitation: it is the only way to be sure nothing is writing behind you.

Sync positions have a durable checkpoint before classic sync, sliding sync,
or dehydrated-device responses issue their tokens. The checkpoint survives
mailbox drains and receipt-only activity. A restart must allocate future
positions above tokens clients already hold, even when push is disabled.

The server keeps the state of each MSC4186 connection in memory only. After a
restart, or after one hour without a request, the server answers the `pos` of
a client with `M_UNKNOWN_POS`. The client then starts its connection again,
and the server sends one initial response for its visible window. To-device
messages have their own acknowledgement token, which is not `pos`. Thus the
client loses no messages. The data on disk does not change, so you do not need
a migration.

## Backup

```
spindle backup <config> <file>
```

Writes a consistent snapshot of the store. It **refuses to overwrite an
existing file** — a backup that silently replaces the good copy with a bad
one is discovered at restore time, which is the worst possible moment.

The archive carries rows, **not media blobs**. Media lives outside the store
(on disk or in S3) and is copied separately. This is deliberate — a backup
file that inlined a terabyte of media would be a file nobody takes — but it
means a restore is only half done when the rows are in.

The command writes the rows from the snapshot to the file one at a time. Thus
a backup needs memory for one row, not for the full store (#743).

## Restore

```
spindle restore <config> <file>
```

Refuses a store that already holds rows. A restore into a populated store is
a *merge*: rows the target holds and the backup does not survive it, so the
result matches neither the backup nor the original, and it looks like a
success. Restore into an empty store, or clear the old one first.

The restore reports which media the rows it wrote still need. A row-only
restore leaves a server that is indistinguishable from a healthy one until
somebody asks for a file, so the report is how you find out before your users
do.

## Verifying media

```
spindle verify-media <config>
```

The same audit a restore prints, on its own. Blobs go missing without a
restore in sight — a bucket lifecycle rule, a half-copied directory, a disk
that came back smaller. Exits non-zero when anything is absent, and names the
media IDs rather than only the content hashes: the hash is what the backend
calls it, the ID is what you have to look for in your other copy.

## Verifying the store

```
spindle verify <config>
```

This command checks every room. It reads each record, the whole chain and
every state root. Run it after a crash, a restore or a disk fault. It names
each room that fails and exits non-zero. A read error is reported as an
error, not as a missing node. The server must be stopped.

## Collecting unreachable state

```
spindle gc <config> [--dry-run] [--max-marks N]
```

This command deletes the state-trie nodes that no stored record reaches
(#742). The state of a room is a trie of content-addressed nodes. One node
can occur in the state of many entries and rooms. To find a dead node, the
command must examine all records. Before this command, nothing deleted
nodes, and unused nodes stayed on disk. Examples are the intermediate states
of a backfilled gap, the rows of an interrupted import, and the trie of a
deleted room.

The command marks each node that a stored root can reach. Log entries,
sidelined events and backfilled gap events hold these roots. The command
reads a shared node only once. Then it deletes all other nodes.

The command prints the number of rows that hold roots, the reachable nodes
and their bytes, and the deleted nodes and their bytes. `--dry-run` prints
the same report and deletes nothing. A second run deletes nothing.

**It does not guess.** It stops before any delete if a reachable node is
missing or has the wrong hash. It also stops if it cannot read the root of a
record. A sweep from an incomplete mark deletes live state.
The one exception is a current-state cache row that does not decode. A room
load already ignores such a row, so the command deletes it.

The sweep deletes in batches of 4096 nodes. It does not hold all dead nodes
in memory.

The set of reachable nodes has a memory bound. `--max-marks N` sets how many
addresses stay in memory, 4194304 by default, about 200 MB. When that many
are held, the command moves them to a scratch database in a directory next to
the store, named like the storage path with `.gc-scratch` added. The command
removes the directory when it ends, and clears one that a crashed run left
before it starts. Keep free disk for it: it holds one 32-byte address for each
reachable node that did not fit in memory. The answer is exact for every `N`.
A Bloom filter would not be: one false positive keeps a live node out of the
mark and the sweep then deletes it. The report shows the peak number of
addresses held in memory and how many went to disk.

**Intern rows stay.** The command does not delete `StateKeyIntern` rows. The
server loads the whole table at start, and a room that sends many unique state
keys makes it grow. The rows cannot be removed one by one. The table must stay
dense, because the store refuses to open onto an id sequence with a gap. The
ids sit inside the content of state nodes, so renumbering would rewrite every
node and change its address. That is a migration, not a sweep. #818 stays open
for it.

**Offline only**, and not available as a background task. The key of a node
is its content. When a server makes a node again, it writes the same key
that the sweep can delete. The two writes look the same.

Thus a sweep that runs during an append can delete a node that the append
needs. A snapshot does not help, because the snapshot already holds that
row. Make a backup first if you want a way back.

## Importing password hashes

```
spindle set-password-hash <config> <localpart> < hash
spindle set-password-hash <config> < hashes
```

Stores password hashes that another system made (#611): Argon2 in PHC
form, or bcrypt. This is usually the `user_passwords.hashed_password` of
a Matrix Authentication Service. Those users then sign in to Spindle with
the passwords they already have. The hashes come from stdin, never the
command line, so they do not show in a process listing or shell history.

With a localpart,
stdin is the hash of that one account. Without one, each line is
`<localpart> <hash>` (`@user:server` works too, and the command does not read
blank lines and `#` comments).

The command validates each hash before it writes it. An Argon2 hash must be
`argon2id`, `argon2i` or `argon2d`, version 16 or 19, with exactly the
`m`/`t`/`p` parameters. `m` is 256 MiB at most, and `t` and `p` are 16 at
most. A bcrypt hash must be `$2a$`, `$2b$` or `$2y$`, with a cost of 14 at
most. The command refuses all other hashes (pbkdf2, a keyed
`keyid=`/`data=` hash). If this server cannot verify a stored hash,
nobody can enter that account.

A hash made with a pepper that the string does *not* record (the
per-scheme `secret` of MAS) looks ordinary. This command accepts it, but
it never verifies. For MAS, use `spindle import-mas` instead: it reads the
schemes from the MAS configuration and stores each secret with its hash
([delegated-auth.md](delegated-auth.md#moving-from-mas-to-the-built-in-provider-797)).

The
accounts must already exist (the Synapse importer makes them). The command
names a refused line by line number and localpart, never with its hash.
If it refused a line, it exits non-zero. Like each command here, it works
offline. For a live server, use
`POST /_spindle/admin/v1/users/{user_id}/password_hash` with
`{"password_hash": "...", "logout_devices": false}`. This also works while
authentication is still delegated, so hashes can land before a cutover.

## Issuing a password-reset link

```
spindle issue-reset-link <config> <localpart> [--ttl 24h]
```

This is for a user who cannot sign in, on a server that sends no mail
(or for any user). It prints a link to the *choose a new password* page of
the built-in provider, on the configured issuer. The link works one time.
Give it by a channel you trust. The person who opens it can set the
password of the account, and that signs each device out.

`--ttl` takes `30m`, `24h`, `2d` or seconds: a day by default, a week at
most. Only the newest link of an account works. A new link (or a mailed
one that the user asks for) retires this one. The server keeps only a
digest of the token.

The command needs `auth.builtin_oidc` and works
offline, like the other commands here. For a live server, use
`POST /_spindle/admin/v1/users/{user_id}/reset_link` (optional body
`{"ttl": "2h"}`). It records the link in the audit log without the token.
Users can also recover on their own with the recovery codes of the
account pages. See [delegated-auth.md](delegated-auth.md).

## A full disk

When the disk fills, the store refuses the write that does not fit. The
client gets a 500 for that request. From then on the store refuses every
write until the process restarts, because fjall locks its database after a
failed journal write. Nothing the server acknowledged is lost.

What the probes say:

- `/ready` answers 503 from the first refused write. A load balancer then
  sends no clients to a server that cannot write.
- `/health` stays at 200. The process is good and the disk is not. A restart
  onto the same full disk only adds a crash loop.
- Reads continue. `/sync` and `/messages` serve the history up to the last
  acknowledged event.

To recover, make space on the disk, then restart the server. Make a
real amount of space, not a few megabytes: at start, the store must flush
what it recovered before it accepts a write. In the drill, a 64 MiB disk
with 2 MiB free did not recover, and with 16 MiB free it did.

`just drill-disk-full` runs the drill. It mounts a 64 MiB tmpfs with sudo,
then fills it under the store and under a server. CI runs it on each pull
request. The two tests are `crates/spindle-store/tests/disk_full.rs` and
`crates/spindle-server/tests/disk_full.rs`.

## Migration

```
spindle migrate <config> [--dry-run] [--progress text|json]
spindle migrate --list [<config>]
```

Moves a store forward to the schema the current binary speaks.

**The server never migrates on its own.** A binary that rewrites the store the
moment it starts is a change you cannot back out of: by the time you know it
happened, the old bytes are gone. So a store at another schema makes the
server *refuse to start*, naming this command, and the rewrite waits until you
ask for it — with the chance to take a backup first.

`--dry-run` prints the plan and writes nothing. Use it. It is where you find
out whether the plan contains a step you cannot undo.

`--list` prints each step of this binary: its id, the schema it starts from,
the schema it goes to, and if you can undo it. Without a config, the list
tells you which schemas this release can move a store from. With a config, it
also gives the status of each step on that store. The status is `applied`
(with the time and the number of rows), `pending`, `pending, interrupted`
(with the position), or `not needed`.

### Take a backup first

Not a formality. `migrate` is the one lifecycle command that rewrites data in
place, and a backup taken beforehand is the only route back from a step marked
irreversible.

### Rollback limits

Reversibility is declared per step and reported before anything runs.

| step is | means |
|---|---|
| **reversible** | the older binary can still read the store afterwards. No step is reversible today, and an older binary refuses a store with a newer marker. |
| **irreversible** | it cannot. Going back means restoring the backup taken beforehand, and losing everything written since. |

A plan containing one irreversible step is irreversible as a whole, and
`migrate` says so on its first line, before the steps.

Two limits worth stating plainly, because neither is obvious:

- **There is no `migrate --down`.** A reversible step is reversible because
  the *older binary* can still read what the newer one wrote, not because
  Spindle can walk the step backwards. Nothing undoes a migration in place.
- **A binary older than its store cannot be helped.** `migrate` reports no
  path and touches nothing. The steps that would be needed have not been
  written, because the version they lead to did not exist when that binary was
  built. Upgrade the binary, or restore a backup from before the migration.

### Steps

Each step has an id. The id does not change, and no other step gets it.
When a step is complete, `migrate` writes a ledger row with the id in the
store. The same commit moves the schema marker to the schema that the step
goes to. Backups copy the ledger with the other rows.

| id | from | to | rollback | what it does |
|---|---|---|---|---|
| `intern-state-keys` | 1/1/2 | 1/1/3 | irreversible | rewrites the state tries of version 2 with interned key ids (#79) |

The schemas are key schema/record schema/content digest, as in
[Format versions](#format-versions). A new step must have a row in this
table. `crates/spindle-store/tests/schema_migration.rs` fails if a step id
is not here.

### Progress

A step tells you its phase and its count while it runs, on stderr (#656).
Each line has the step id and the phase, and counts in a stated unit:
records, rooms or nodes.

- When a phase knows its total, the line shows done/total and a percentage.
  After one second, it also shows a rate and an ETA.
- When a phase does not know its total, the line shows the count and
  "total unknown". The count changes while the work continues. There is no
  percentage and no ETA.

Each phase writes a line when it starts and when it ends. Between these, it
writes one line each 5 seconds at most, so a long step does not fill the log.

`--progress json` writes each line as one JSON object, for scripts and
Kubernetes jobs. The `event` field is `started`, `progress`, `applied` or
`error`. A `progress` object has `step`, `phase`, `stage`
(`started`/`running`/`finished`), `unit`, `done`, `total`, `percent`,
`resumed`, `elapsed_seconds`, `rate_per_second` and `eta_seconds`. A field
has the value `null` when the step cannot calculate it. The report on stdout
does not change.

The `intern-state-keys` step has three phases:

| phase | unit | total |
|---|---|---|
| `count` | records | unknown: this phase finds the total |
| `convert` | records | known |
| `delete-v2-nodes` | nodes | known |

### What a failure leaves behind

The schema marker moves only at the end of a step, after the step is
complete. It never moves during a step.

If the marker of a store claims a schema that its data does not have, no
check refuses the store. Then each read can be wrong. The marker exists to
stop this silent failure, and `migrate` must not cause it. Thus a failed step
leaves the marker at the schema that the step starts from. The store
continues to name the version that a binary can read.

You can repair the cause and run `migrate` again, without a restore from the
backup. Steps that are complete stay complete. The next run starts at the
step that failed.

A long step also writes a progress record in the store when a part of its
work is durable. The `intern-state-keys` step writes one after each room. If
the step stops (an error, a kill, a power failure), the next `migrate` reads
the record and continues after the last room in it. `--dry-run` and `--list`
show this position. `migrate` locks the store while it runs. Thus, during
the run, stderr is where you see the progress.

A step continues from a record only if the record has its id. If the record
has a different id, `migrate` deletes it, and the step starts again from the
start. Each step must give the same result when it runs again from the
start or from its record.

### Format versions

"The storage format" is four formats stacked, each with its own number, and
a bug report or a migration step has to say which one it means:

| layer | named by | now | what a bump means |
|---|---|---|---|
| **key schema** | `KEY_SCHEMA_VERSION` in `spindle-core` | 1 | the byte layout of keys: a keyspace discriminant reused or reordered, or a key's fields moved. *Adding* a keyspace is not a bump: every existing key keeps its bytes and its meaning. |
| **record schema** | `RECORD_VERSION` in `spindle-store` | 1 | the encoding of the values under those keys (log entries and bodies), which carry their version as their first byte. |
| **content digest** | `CONTENT_DIGEST_VERSION` in `spindle-core` | 3 | how content addresses are *derived*: a domain tag, a length width or a field order in the hashing. Keys and records are untouched by such a change, which is why it has its own number (#78): a store under the old derivation would open and misread every node address. |
| **engine format** | the major version of `fjall` in `Cargo.toml` | 3 | the on-disk layout of the store itself: journal, segments, the engine's own `version` file. Spindle does not choose it and cannot rewrite it. |

The first three are what the schema marker records and what `migrate` moves
between; all three are pinned by
`crates/spindle-store/tests/format_compatibility.rs`, whose fixtures are bytes
written under the versions they name, so a bump fails a test until fixtures
for the new version *and* a decision about data written under the old one
exist. The fourth is what the marker cannot describe, because the marker is
stored inside it.

The transitions so far, numbered so they can be referred to:

| # | layer | from | to | where | how a store crosses it |
|---|---|---|---|---|---|
| 1 | engine format | fjall 2 | fjall 3 | #193 | it does not. fjall 3 refuses a v2 directory with `InvalidVersion(Some(V2))` and has no in-process upgrade. Restore from a backup taken under fjall 3, or start a fresh store. |
| 2 | content digest | 1 | 2 | #330 | it does not, yet. The store is refused as `content_digest 1` (a store from before the marker existed counts as 1 if it holds any row), and no migration step re-derives the addresses. Start a fresh store. |
| 3 | content digest | 2 | 3 | #79 | `spindle migrate` runs step `intern-state-keys`: it rewrites state tries with interned keys and persists their intern rows. Irreversible; restore the pre-migration backup to return to version 2. |

The first two were accepted deliberately, because no Spindle had data to lose. They
are kept on the books rather than forgotten because each is an example of
what the machinery below does *not* do: transition 1 is the case it cannot
help with, and `crates/spindle-store/tests/backend_compatibility.rs` holds
fixtures written under fjall 2 to prove the refusal is clean and explains
itself; transition 2 is a step the table could hold and does not, because
nobody has needed it. Key and record schemas have never moved.

### The current state of the table

The first data rewrite is the version-2 to version-3 content-digest step (#79),
`intern-state-keys`. It converts roots in the linear log, sidelined records and
gap history, and writes the intern rows with their new nodes. It deletes the
old nodes after all rooms have converted, because rooms can share a content
address. Take a backup before this irreversible step.

A partial run keeps the old marker. The next run continues after the last
converted room and finishes the remaining work. The old nodes of the rooms
that the next run does not convert again stay on disk without a reference.
`spindle gc` deletes them.

The migration machinery is covered by `crates/spindle-store/tests/schema_migration.rs`;
the actual rewrite and reopening are covered by `tests/state_migration.rs` in
the same crate. The intern table is part of the backup: losing its rows loses
the meaning of the ids in state nodes. Version 1 still has no migration path.
