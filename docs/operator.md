# Spindle Operator

`spindle-operator` is the control plane for a Spindle deployment. It is a
separate process with its own state on its own disk. Thus it stays up when
Synapse, Spindle or their ingress stops. A migration needs it most at those
times.

This page covers the foundation from issue #457: the service, the durable
operation engine, the session model and the API contract. It also covers the
first console pages from #458. The migration workspace (#459) and the ESS
driver (#460) build on the same API.

## Run it

```sh
cargo run -p spindle-operator -- --config spindle-operator.toml
```

`deploy/operator/spindle-operator.example.toml` is a full example. The file
holds no secret. The OIDC client secret and each driver credential are
references of the form `env:NAME` or `file:/path`.

## Console

Open the operator's public URL in a browser. `/` goes to `/console/`, which
asks you to sign in and then shows three pages:

- **Now** tells you what needs a person, which change is active, and how each
  homeserver answered its last probe. It also gives the next safe action. A
  header on every page shows authority, write state, the active change and
  failed probes. Authority and write state come from the latest assessment:
  a driver reports them as findings with the codes `authority` and `writes`.
  When no driver reports them, the header says so.
- **People & access** finds accounts by user ID or display name. It shows an
  account's status, devices and rooms.
- **Rooms & safety** lists rooms and recent reports. It shows a room's
  settings, block state, deletion tasks, reports and members.

The pages are three static files in the operator binary. They read only
`/_spindle/operator/v1`, and the browser holds only the session cookie. Their
content security policy allows script, style and requests from the operator's
own origin, and nothing else.

The pages work with a keyboard and a screen reader. They have a skip link,
landmarks, table captions and headers, visible focus, and a live region for
results. They meet WCAG AA contrast in light and dark mode, and they work on a
narrow screen. They have no animation. Status always has a text label, not
only a color.

The first version does not change anything on a homeserver. To lock an
account or block a room, use an operation. The console does not offer those
actions yet.

### People and rooms

To browse a homeserver, give its connection a `credential` reference to an
admin access token, for example `"credential": "env:SPINDLE_ADMIN_TOKEN"`.
The operator calls the homeserver's Synapse admin API
(`/_synapse/admin`) with that token. Spindle and Synapse both serve this API.
The token goes only to the homeserver.

| Route | Purpose |
|---|---|
| `GET /connections/{id}/people?search&from&limit` | accounts |
| `GET /connections/{id}/people/{user_id}` | one account, its devices and rooms |
| `GET /connections/{id}/rooms?search&from&limit&order_by` | rooms |
| `GET /connections/{id}/rooms/{room_id}` | one room, its members, block, tasks and reports |
| `GET /connections/{id}/reports?from&limit` | reports, newest first |

Each route needs the viewer role. Email addresses, linked identities and
device IP addresses are shown only to the operator role. The operator copies
only named fields from each answer, so a new field on the homeserver does not
reach the browser.

When a lookup fails, the error code says why:

| Code | Meaning |
|---|---|
| `no_credential` (409) | the connection has no credential |
| `credential_unavailable` (503) | the operator cannot read the secret |
| `homeserver_unreachable` (502) | no answer, or no answer in time |
| `homeserver_refused` (502) | the homeserver refused the credential |
| `homeserver_error` (502) | the homeserver answered with an error |

On the account and room pages, a failed secondary lookup does not fail the
page. The page lists that part under `unavailable` and shows the rest.

## State

The operator keeps one file, `journal.jsonl`, in its data directory. A lock
on `journal.lock` stops a second operator process from using the same
directory. If an append fails, the operator removes the partial line. If it
cannot remove the line, it refuses all later writes. Each
change is one JSON line. The engine syncs the line to disk before it changes
its memory or answers the request. At startup the engine reads the file again
and gets the same state back.

The journal is also the audit trail. No code path edits or removes a line.
`GET /_spindle/operator/v1/audit` reads it, with session hashes and stored
replies removed. A crash can cut the last line short. The engine drops that
line, because no caller saw its write succeed.

Evidence content goes to `artifacts/<id>.json`, and the journal keeps its
SHA-256 hash. When evidence expires, the operator deletes the file. The record
and the hash stay in the audit trail.

## Operations

An operation is one driver action on one deployment, for example `quiesce`.
The driver plans the action as a list of steps. Each step states its risk,
whether it changes the deployment, and whether the driver can undo it.

The engine runs the steps in order. Before a step runs, the journal records
`step_started`. After the step, the journal records the checkpoint and the
evidence. After a restart, the engine applies these rules:

- It never runs a completed step again.
- For a change that started but has no checkpoint, it asks the driver to
  observe the deployment. It runs the step again only if the driver reports
  no effect.
- If the driver cannot tell, the operation stops in `attention_required`. A
  person then resumes it with `"resolution": "applied"` or `"not_applied"`.

### Leases

An operation takes its deployment's lease when it starts. The lease is in the
journal, so it survives a restart. A second operation on the same deployment
gets `409 lease_held`. The engine releases the lease when the operation
succeeds, stops after a cancel, or rolls back.

### Approvals

The policy names the step risks that need approval. By default, every
`high` step needs one. The runner stops before such a step in
`awaiting_approval`. An approval must come from a person with the approver
role. That person cannot be the requester. With typed confirmation on, the
approver must type `<operation id>/<step name>`.

### Pause, resume, cancel, rollback

All four are `POST /operations/{id}:<verb>` calls with `If-Match`.

| Verb | Allowed from | Result |
|---|---|---|
| `pause` | `running`, `awaiting_approval` | stops before the next step |
| `resume` | `paused`, `failed`, `attention_required` | runs from the first open step |
| `cancel` | any state before the end, except during a rollback | stops and releases the lease, with no undo |
| `rollback` | `paused`, `failed`, `attention_required`, `awaiting_approval` | undoes changes, last first |

The driver cannot undo some steps, for example a traffic switch after the
new server accepts writes. When such a step has run, `rollback` gives `409
write_boundary_crossed`. To recover, start a new operation that goes forward.

## Drivers

A driver knows one kind of deployment. The engine knows how to run steps in a
safe order. Each driver has five calls: `plan`, `assess`, `execute`,
`observe` and `compensate`. The last one must be safe to repeat.

A driver program in another language connects through
`[drivers.<name>]` in the configuration. For each call, the operator starts
the program and writes one JSON document to its stdin:

```json
{"api": "spindle.operator.driver/v1", "call": "execute",
 "deployment": {}, "action": "quiesce", "params": {},
 "operation": "op_…", "step": {}, "checkpoints": []}
```

The program writes `{"ok": <result>}` or `{"error": "<text>"}` to stdout. The
operator accepts an `ok` only if the program exits with success. A reply must
be smaller than 4 MiB. The operator logs at most 64 KiB of stderr, with
secrets removed. Each call runs in its own process group, and a timeout stops
the whole group. The operator removes secrets from every driver error and
finding before it stores or returns them. The operator gives the program a
clean environment. It adds only `PATH` and the
secrets from `[drivers.<name>.secrets]`. Thus secret values never go into the
request, the journal or the logs. The operator stops a call at
`timeout_secs`.

## Sessions and roles

The browser signs in with OIDC. The flow is the authorization code flow with
PKCE. The operator checks the issuer, audience, expiry and nonce of the ID
token. The token comes direct from the token endpoint over TLS, so the
operator does not check its signature. OIDC Core section 3.1.3.7 lets a client do this.

The session cookie is `__Host-spindle-operator`, with `HttpOnly`, `Secure` and
`SameSite=Strict`. The journal keeps only a hash of the session id. Sessions
last 30 minutes by default and 8 hours at most.

Each `POST` and `PUT` must send the `X-CSRF-Token` header. Get its value from
`GET /_spindle/operator/v1/session`. If the request has an `Origin` header,
it must be the operator's own origin.

Roles come from the ID token. A `group:` entry matches a value of the roles
claim. A `sub:` entry matches the subject of one person. A person with no role gets no
session.

| Role | Can |
|---|---|
| viewer | read views, resources, evidence and the audit trail |
| operator | add connections and deployments, run assessments, start and steer operations |
| approver | approve high-risk steps and change the policy |

## Secrets

No resource holds a secret value. A resource holds a reference, and the
operator reads the value only when it uses it. The operator refuses a secret in
the settings of a deployment or in the parameters of an operation. To name a
credential, use a field that ends in `_ref`, for example
`"admin_token_ref": "env:ADMIN_TOKEN"`.

The operator also removes secrets from evidence, checkpoints, driver errors
and audit output. It looks for secret key names and for token shapes. The
shapes are Matrix access tokens, bearer tokens, PEM private keys and the
lines of a Synapse key file.

## API contract

All routes are under `/_spindle/operator/v1`. The browser console and a
future `spindlectl` use the same routes.

- Every `POST` needs an `Idempotency-Key` header. A retry with the same key
  and body gets the first successful reply again, with
  `Idempotent-Replayed: true`. The operator does not store a refusal, so a
  retry after a refusal is checked again. The same key with a different body
  gets `422 idempotency_key_reused`. If the client disconnects before the
  reply, the operator releases the key.
- Each resource has an `ETag`. A change to a resource that exists needs
  `If-Match`. Without it, the reply is `428`. With an old value, the reply is
  `412`.
- Errors are `{"error": {"code": "…", "message": "…"}}`. Clients use the
  code, not the message.

| Route | Purpose |
|---|---|
| `GET /view` | leases, active operations, items that need a person, last probes |
| `GET, POST /connections` | homeserver endpoints, each with a secret reference |
| `POST /connections/{id}:probe` | check `/_matrix/client/versions` |
| `GET, POST /deployments` | deployments and their drivers |
| `GET, POST /assessments` | driver findings for a deployment |
| `GET, POST /operations` | operations |
| `POST /operations/{id}:pause` | also `:resume`, `:cancel`, `:rollback` |
| `POST /operations/{id}/approvals` | approve the waiting step |
| `GET /operations/{id}/events` | server-sent events, with `Last-Event-ID` |
| `GET /artifacts/{id}` | evidence until it expires, then `410` |
| `GET, PUT /policies/default` | the approval policy |
| `GET /audit` | the journal, with `after`, `limit` and `operation` filters |

The event stream sends the history after `Last-Event-ID`, then live changes.
It ends after the operation reaches `succeeded`, `cancelled` or
`rolled_back`.

## Tests

`crates/spindle-operator/tests/operator_api.rs` tests the contract over TCP.
It uses a real OIDC login against a test provider and a driver that models a
deployment. The tests cover each acceptance criterion of #457:

- The console works while both homeservers are down.
- A restart resumes from checkpoints, and no change runs twice.
- A persisted lease stops a second operation.
- The audit trail records the actor, request, approval, steps and evidence.
- The server enforces the viewer, operator and approver roles.
- No secret reaches the browser, the journal or the audit output.
- Idempotency, `If-Match`, cancel and rollback work as this page says.
