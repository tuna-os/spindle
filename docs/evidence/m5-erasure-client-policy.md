# Account erasure in client views

This work addresses #576 for the Synapse migration rehearsal.
Production has not changed.
The earlier rehearsal report records the code that existed at that time.
This work keeps the source account flags and applies them when clients read events.

## Policy

An erased local sender keeps a limited audience. A reader who held joined
membership at the event can still see its content. Other readers receive
the room version's redacted form.
The decision uses the persisted state at that event, not current membership.
Missing state data refuses the read. An auth outlier has no proof of membership
and receives the redacted view.

The filter changes a client copy. It does not rewrite a signed PDU.
The flag that activates this filter is durable. On upgrade, the first read checks
existing accounts if the flag does not yet exist. Flag and password updates share
a lock with erasure writes so they cannot restore an older account flag.

## Read paths

Room readers carry the user who reads. They filter single events, state, members,
pages and context. Search filters before matching, so erased text cannot create
a hit. Notifications use that same search path.

Sync filters its timeline and state. An active policy disables the shared state
render for client responses. `Sliding sync` filters state, timeline, names, avatars
and the member names it uses for the room list. Invite and knock previews filter
before the server strips events. A preview with no state proof gets the
redacted view for erased local senders.

Relation bundles filter their children before they count or choose an edit or
reply. Lists of threads filter replies before they use the relation index. The relations
endpoint filters its returned events.

The filter checks `unsigned.prev_content`
against the predecessor's state. This also applies when the later sender retains
an active account. The server applies the filter to sticky events before it sends them.
Room summaries and directory searches use the user's view.

## Evidence so far

The tests use synthetic data. The repository contains no production PDU.

- The persisted-store test passed for room versions 1 through 12. It checks that
  an earlier member keeps content and a later member cannot see it. It checks
  state, pagination, context, search, sync, predecessor content and a full store
  reopen. The stored federation PDU remains equal to its original value.
- The HTTP test passed for event, context, state, messages, relations, threads,
  ordinary sync, `sliding sync`, search, notifications and invite previews.
- The existing client suites passed 77 tests, including the sync cost checks.
- Workspace Clippy passed with all targets and all features and warnings denied.

All four tests for read budgets passed. The full workspace suite remains active.
A complete source import and a client witness against that store remain migration
gates. These synthetic results do not establish readiness for cutover.
