# Running a Spindle over time

The commands an operator uses between installing a server and retiring one:
backing it up, restoring it, checking its media, and moving its store forward
when the on-disk format changes. Part of #20.

Every one of these opens the store directly, and fjall holds an exclusive
lock, so **they run with the server stopped**. For a restore that is not just
a limitation: it is the only way to be sure nothing is writing behind you.

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

## Migration

```
spindle migrate <config> [--dry-run]
```

Moves a store forward to the schema the current binary speaks.

**The server never migrates on its own.** A binary that rewrites the store the
moment it starts is a change you cannot back out of: by the time you know it
happened, the old bytes are gone. So a store at another schema makes the
server *refuse to start*, naming this command, and the rewrite waits until you
ask for it — with the chance to take a backup first.

`--dry-run` prints the plan and writes nothing. Use it. It is where you find
out whether the plan contains a step you cannot undo.

### Take a backup first

Not a formality. `migrate` is the one lifecycle command that rewrites data in
place, and a backup taken beforehand is the only route back from a step marked
irreversible.

### Rollback limits

Reversibility is declared per step and reported before anything runs.

| step is | means |
|---|---|
| **reversible** | the older binary can still read the store afterwards, and re-stamps the marker on its own terms. Downgrading works. |
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

### What a failure leaves behind

The schema marker is written **last**, and only after every step succeeded.

A store whose marker claims to be current while its data is half-rewritten
would be refused by nothing and misread by everything — exactly the silent
failure the marker exists to prevent, reintroduced by the tool meant to move
past it. So a failed step leaves the marker where it was: the store still
describes itself as the version it can still be read as, and you can fix the
cause and run `migrate` again rather than reaching for the backup.

### The current state of the table

**No schema change has yet needed a data rewrite**, so the migration table is
empty and `spindle migrate` reports "already at this binary's schema" on every
store in existence.

That is worth saying rather than implying otherwise. What exists today is the
machinery and its guarantees, proven by `crates/spindle-store/tests/schema_migration.rs`
against synthetic tables — chaining, the no-path refusal, dry runs writing
nothing, and the marker never landing ahead of the data. Those are properties
of the machinery rather than of any particular step, which is why they can be
established before the first real step is written, under whatever pressure
produced the schema change that needed it.
