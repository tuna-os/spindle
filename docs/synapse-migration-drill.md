# The Synapse migration drill

This page is the test plan for issue
[#263](https://github.com/tuna-os/spindle/issues/263). It is the
acceptance test for the Synapse importer
([#240](https://github.com/tuna-os/spindle/issues/240)). The importer is
not complete until this drill passes.

The drill uses two Synapse servers. They federate with each other and
they have a long shared history. You move them to an isolated network.
Then you convert one of them to Spindle in place. The other server must
not see a change, except that its peer now runs different software.

## 1. What the drill finds

The importer has a fixture test (`scripts/synapse-fixture-test.py`). That
test reads a small Synapse database and compares state. It does not
find these problems:

- A cut-over that changes the `server_name` or the server key. Then a
  peer rejects new events, or it cannot verify the signatures on old
  events.
- A difference between the Spindle federation sender and the Synapse
  federation sender. This difference shows only for a peer that has a
  long shared history with the server.
- A room whose state on Spindle is different from the state that
  Synapse held before the cut-over.

The fixture test cannot find these problems because it has no peer.
This drill has a peer.

## 2. The rig

| Part | Role |
|---|---|
| Synapse A | Stays Synapse for all of the drill. It is the witness. |
| Synapse B | Becomes Spindle B at the cut-over. |
| Resolver | A private DNS server. It resolves the two server names, and no other names. |
| Clients | One test account on each server, and one client per account. |

Use real servers with real history when you can. Two servers on the
public federation with many rooms, many members and many state events
give the best result. A server with only a few new rooms does not test
the long-history case.

The rig needs Docker or two hosts. Thus it runs in CI or on lab
hardware. It does not run in the agent sandbox.
`scripts/complement.sh` and the `compliance-interop` job in
`.github/workflows/compliance.yml` already run Spindle against Synapse
with a fixed `server_name` for each. The `mesh-seam` job already uses a
private resolver. The drill uses the same parts with two Synapse
servers and a longer warm-up.

## 3. Prerequisites in Spindle

The drill cannot start until these items are complete. Each item is a
gate. Do not start the drill to find out the status of a gate.

| Gate | Status on 2026-10-02 | Tracked in |
|---|---|---|
| The importer writes rooms into a Spindle store, and a command runs it. Today `import::replay` builds the log in memory only. | Open | #240 |
| A reader for the Synapse PostgreSQL database. Today only the SQLite reader is on `main`. | Open | #240, closed PR #462 |
| Spindle loads the Synapse server key with its key ID. Today `signing.rs` makes its own key with the fixed version `ed25519:0`. | Open | #240 |
| Spindle federates rooms in legacy room versions, for example version 10. | Open | #456 |
| A client that signs in after the cut-over can decrypt history. | Open | #240 |

The gate for the server key is the most important gate for this drill.
Synapse key IDs have the form `ed25519:a_XXXX`. Peers keep the public key
under that ID. Spindle B can sign with a new key, or with the same key
under a new ID.

In both cases, Synapse A must get a new key from Spindle B. Old
signatures then refer to a key that Spindle B does not publish. The
drill must show that Synapse A sees no change in the key.

## 4. Procedure

Do the steps in sequence. Record the result of each step before you
start the next step.

### 4.1 Warm-up on the public federation

1. Start Synapse A and Synapse B with their production `server_name`
   values.
2. Make sure that there are rooms on the two servers in common.
3. Include a room with a contested fork and an encrypted room.
4. Include one room for each room version on the servers.
5. Record a baseline for each shared room on each server.
   Record the current state map, the forward extremities and the most
   recent event ID.

### 4.2 Move to the isolated network

1. Stop both servers.
2. Move them to a network that can reach only the two servers and the
   private resolver.
3. Set the resolver to give the same names and the same ports as on
   the public network. Do not change the TLS certificates or the
   server keys.
4. Start both servers.
5. Send messages in both directions in each shared room. Each message
   must arrive on the other server.

If messages do not arrive at this step, the fault is in the rig, not in
Spindle. Correct the rig before you continue.

### 4.3 Seal Synapse B

1. Stop new client traffic to Synapse B.
2. Let the outbound federation queue on Synapse B become empty.
3. Stop Synapse B.
4. Make a backup of its database, its media store and its server key.
   The rollback in section 4.7 uses this backup.

### 4.4 Convert Synapse B to Spindle B

1. Run the importer against the stopped database of Synapse B.
2. For each room, the importer compares the state that Spindle folds
   forward with the current state that Synapse holds. Record each
   divergence. A divergence in a room with a contested fork is a
   result to examine, and not always a fault. The Spindle fork merge (SPEC §9.2) and
   Synapse state resolution are different algorithms. Thus they can
   give two different results for the same contested fork.
3. Give Spindle B the Synapse server key with its original key ID.
4. Start Spindle B on the same address, with the same `server_name`
   and the same TLS certificate.
5. Do not let clients connect yet. Sign in with the test account.
   Make sure that the account, its rooms and its devices are present.

### 4.5 Federation after the cut-over

1. From Synapse A, get the server keys of Spindle B. The key ID and
   the public key must be equal to the values from section 4.1.
2. Send a message from Spindle B into each shared room. Synapse A must
   accept it.
3. Send a message from Synapse A into each shared room. Spindle B must
   accept it.
4. Change room state from each side, for example a topic or a power
   level. Both servers must show the same new state.
5. Make Synapse A fetch an old event from Spindle B through
   `/_matrix/federation/v1/event`. The signature on the event must
   verify against the key from step 1.
6. In the encrypted room, send a message from each side. Make sure that
   the client on each side can decrypt it.

### 4.6 Observation

Let the two servers operate for at least 24 hours with traffic in
both directions. Look at the federation backlog and the error rate
(runbooks/SpindleFederationBacklog.md and
runbooks/SpindleServerErrors.md). Synapse A must not log signature
failures or rejected events from Spindle B.

### 4.7 Rollback rehearsal

Do this step before Spindle B writes new events that Synapse A has not
seen. After that point, a rollback to Synapse loses those events.

1. Stop Spindle B.
2. Restore the backup from section 4.3.
3. Start Synapse B.
4. Send messages in both directions. Each message must arrive.

Then do sections 4.4 to 4.6 again and keep Spindle B.

## 5. Pass criteria

The drill passes when all of these are true:

- Synapse A sees the same key ID and the same public key for the
  server before and after the cut-over.
- Messages and state changes federate in both directions after the
  cut-over, in each shared room.
- For each room, the state on Spindle B is equal to the state that
  Synapse B held at the seal. A room that is different has a recorded
  reason, and a maintainer accepts that reason.
- Synapse A can verify the signatures on old events from Spindle B.
- The test clients can decrypt messages that were sent before and
  after the cut-over.
- The rollback rehearsal in section 4.7 succeeds.

## 6. Evidence

Put the result of the drill in `docs/evidence/`. Include these items:

- The rig description and the revision of each server.
- The baseline from section 4.1.
- The divergence list from section 4.4.
- The result of each step.
A drill that fails is also evidence. Record it in the same way.

Issue [#459](https://github.com/tuna-os/spindle/issues/459) adds a
workspace for migrations to the Spindle Operator. It will automate
these steps. Do the drill by hand first. Automation comes after the
manual procedure passes.
