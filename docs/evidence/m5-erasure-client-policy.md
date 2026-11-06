# Account erasure in client views

This work addresses #576 for the Synapse migration rehearsal.
Production has not changed.
The earlier rehearsal report records the code that existed at that time.
This work keeps the source account flags and applies them when clients read events.

## Policy

Spindle uses the Synapse rule from `synapse/visibility.py`.

An erased local sender keeps a limited audience. A reader who held joined
membership at the event can still see its content. Other readers receive
the room version's redacted form.
The decision uses the persisted state after that event, not current membership.
An auth outlier has no proof of membership and receives the redacted view.

The reader's own membership event uses the Synapse rule for that event.
The rule takes the more joined value of the new and the previous membership.
Thus a joined member sees their ban in full.
A kick from a joined membership does not count as joined, so the reader gets
the redacted kick.

The filter changes a copy that the server sends. It does not rewrite a signed PDU.

## Read paths

Timeline reads use the filter: single events, pages, context windows, the sync
timeline, the `sliding sync` timeline, sticky events, relations, threads and
notifications. Relation bundles filter their children before they count or
choose an edit or reply.

Room state does not use the filter. This includes `/state`, the sync state block,
`required_state`, members, room summaries, the directory and invite previews.
Synapse also does not apply the filter to state. Before this change, the filter
applied to state too. Then a later member got an `m.room.encryption` event with
no content. A client can then show an encrypted room as a room without encryption.

Search matches the filtered copy, so erased text cannot make a hit. Synapse
matches the stored text and returns the redacted event. That result tells a
later member that the erased user wrote the search term. Spindle does not
return it.

A state event carries the content of the event that it replaces in
`unsigned.prev_content`. The filter also checks that content against the
earlier sender.

Federation reads send the redacted form of each event from an erased local sender
to every server. These reads are `/event`, `/backfill` and `/get_missing_events`.
Synapse does the same. The redacted PDU keeps its hashes and
signatures, so it keeps its event ID. The state and auth chain reads send the
full PDU, because a server needs them to authorize events.

## Cost

The account store keeps an erasure generation. Each change to an erasure flag
increases it. When no account has an erasure flag, the generation is zero and
a read does no more work.

Otherwise the room store keeps the set of erased users for each generation.
Each read gets that set with one marker read. Thus the check for each event does
not read the store. A test counts store reads on six endpoints before and after
an erasure. The counts are equal.

## Evidence so far

The tests use synthetic data. The repository contains no production PDU.

- The persisted-store test passed for room versions 1 through 12. It checks that
  an earlier member keeps content and a later member cannot see it. It checks
  the own membership rule, state, pagination, context, search, sync,
  predecessor content and a full store reopen. The stored federation PDU
  remains equal to its original value.
- The HTTP tests passed for event, context, state, messages, relations,
  threads, ordinary sync, `sliding sync`, search, notifications, invite
  previews and room summaries.
- The federation test passed for `/event`, `/backfill` and `/get_missing_events`.

A complete source import and a client witness against that store remain migration
gates. These synthetic results do not establish readiness for cutover.
