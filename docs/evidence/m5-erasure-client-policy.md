# Account erasure in client views

This work addresses #576 for the Synapse migration rehearsal.
Production has not changed.
The earlier rehearsal report records the code that existed at that time.
This work keeps the source account flags and applies them when clients read events.

## Policy

If a local sender has been erased, a reader who was joined at the event can
still see its content. Other readers receive the room version's redacted form.
The decision uses the persisted state at that event, not current membership.
Missing state data refuses the read. An auth outlier has no proof of membership
and receives the redacted view.

The filter changes a client copy. It does not rewrite a signed PDU.
The flag that activates this filter is durable. On upgrade, the first read checks
existing accounts if the flag does not yet exist. Flag and password updates share
a lock with erasure writes so they cannot restore an older account flag.

## Read paths

Room readers carry the reading user. They filter single events, state, members,
pages and context. Search filters before matching, so erased text cannot create
a hit. Notifications use that same search path.

Sync filters its timeline and state. An active policy disables the shared state
render for client responses. Sliding sync filters state, timeline, names, avatars
and the member names it uses for the room list. Invite and knock previews filter
before events are stripped; a pending preview with no state proof gets the
redacted view for erased local senders.

Relation bundles filter their children before counting or choosing an edit or
reply. Thread lists filter replies before using the relation index. The relations
endpoint filters its returned events. A later state event's `unsigned.prev_content`
is filtered using the predecessor's own state, including when the later sender
has not been erased. Sticky events are filtered before they leave the server.
Room summaries and directory searches use the reading user's view.

## Evidence so far

The tests use synthetic data. No production PDU is checked into the repository.

- The persisted-store test passed for room versions 1 through 12. It checks that
  an earlier member keeps content and a later member cannot see it. It checks
  state, pagination, context, search, sync, predecessor content and a full store
  reopen. The stored federation PDU remains equal to its original value.
- The HTTP test passed for event, context, state, messages, relations, threads,
  ordinary sync, sliding sync, search, notifications and invite previews.
- The existing client suites passed 77 tests, including the sync cost checks.
- Workspace Clippy passed with all targets and all features and warnings denied.

The four stricter read-budget tests and the full workspace suite are still running.
A complete source import and a client witness against that store remain migration
gates. These synthetic results do not establish readiness for cutover.
