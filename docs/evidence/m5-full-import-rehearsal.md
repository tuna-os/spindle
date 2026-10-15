# Full-corpus dark rehearsal of the Synapse importer

This is the evidence for two gates on [#563](https://github.com/tuna-os/spindle/issues/563): **Full importer** and **Full-corpus dark rehearsal**. The run took place on 2026-10-03.

| | |
|---|---|
| Source | Database `synapse` in `spindle-rehearsal/rehearsal-pg`. This database is the restore of the 2026-10-03 production backup of `reilly.asia`. It is 16 GB, with 1,840,117 events and 1,371 users. |
| Media source | PVC `ess/synapse-media-preseed`. A pod mounts it read-only (`scripts/synapse-full-import/media-reader.yaml`) and copies `local_content` and `local_thumbnails`: 2,356 files, 118 MB. |
| Image | `ghcr.io/tuna-os/spindle:rehearsal-801a063@sha256:6dc4861a574a484dc48a0e9bb1b08a707315a93b977d7ffa9d95b95f0f4cbe86` (PR #557 at `801a063`) |
| Command | `spindle import-synapse /conf/spindle.toml "host=rehearsal-pg … dbname=synapse" --media /data/synapse-media --checkpoint /data/import.json` |
| Target | Deployment and ClusterIP Service `fi-dark-spindle` in `spindle-rehearsal`, at `http://fi-dark-spindle.spindle-rehearsal.svc.cluster.local:8008`. The store is on PVC `fi-dark-spindle`, and the full JSON report is `/data/import.json` on that volume. |
| Driver | `scripts/synapse-full-import/run.sh` (`base`, `media`, `import`, `rig-import`, `serve`) |

## Result

| | |
|---|---|
| Rooms with a local joined member | 116 |
| Rooms imported | 102 |
| Rooms excluded | 14, all because of their room version (see below) |
| Rooms with no local joined member | 133, not retained by design |
| Events in the imported rooms (Synapse rows) | 1,133,401 |
| Events imported | 1,124,262. The difference is 9,012 outliers and 127 rejected events. |
| Redactions applied to imported targets | 396,225 |
| Event JSON imported | 994 MB |
| Import time | 659 s for the full run, of which 562 s is rooms. Validation adds 103 s. |
| Store size | 1.3 GB of keyspaces and 128 MB of media blobs, against 16 GB for the Synapse database |
| State divergence | 0 slots in 102 rooms. This is checked twice: on the replay before the write, and on the written store. |
| Validation mismatches | 0 in every domain |
| E2EE rig on this target | PASS for users a, b and c |
| Outbound connections | 0 (netwatch) |

## Per-domain counts

The "Synapse" column counts the rows for local users, or for all rows where a domain is not per user. The "Validated" column is the number of rows that the read-back check compared with Synapse. A validated row passes when Spindle serves the same value.

| Domain | Synapse | Imported | Not imported, and why | Validated (mismatches) |
|---|---|---|---|---|
| Users | 1,371 | 1,371 | None. 1,360 are deactivated (the `telegramgo` bridge puppets) and stay deactivated. 1 is an admin. There are no guest accounts; a guest account would be reported and not imported. | 1,371 (0) |
| Profiles | 1,371 | 1,371 | None | 1,371 (0) |
| Devices | 230 | 212 | 18 are Synapse's hidden rows for cross-signing keys, which are not devices | 212 (0) |
| Device keys | 26 | 26 | None | 26 (0) |
| One-time keys | 1,242 | 1,092 | 150 belong to devices that Synapse deleted | Counted only |
| Fallback keys | 25 | 25 | None. The `used` flag is kept. | Counted only |
| Pending to-device messages | 15,884 | 15,884 | None | Counted only |
| Cross-signing keys | 15 rows, newest per type | 15 | None. Older rows that Synapse keeps for a replaced key are not current. | 15 (0) |
| Cross-signing signatures | 104 | 40 | 64 sign a key that Synapse also no longer holds (61 for deleted devices, 3 for a replaced master key) | 36 groups (0) |
| Key backup versions | 7 | 7 | None | Counted only |
| Key backup sessions | 833 | 833 | None | 5 versions (0) |
| Global account data | 69 | 69 | None | 360 rows with room data (0) |
| Room account data | 291 | 291 | None | As above |
| Room tags (`m.tag`) | 15 | 15 | None | Counted only |
| Push rules | 82 | 82 | None | 82 (0) |
| Pushers | 4 | 4 | None | 4 (0) |
| Read receipts | 33,631 | 7,156 | 24,418 are in rooms that were not imported, 2,025 are for users who left the room, and 32 point at an event outside retained history | 2,066 (0) |
| Room aliases | 3 | 2 | 1 points at a room that was not imported | 3 with the published room (0) |
| Published rooms | 1 | 1 | None | As above |
| Blocked rooms | 0 | 0 | None | Not applicable |
| Server ACLs | Room state | Room state | They are state events, so the state comparison covers them | Covered by the state check |
| Local media | 2,356 files, 115 MB | 2,356 | None. The media IDs do not change. | 2,356, byte for byte (0) |
| Thumbnails | 150 | 150 generated | Spindle makes its own thumbnails. The import makes the 150 sizes that Synapse had. | Counted only |
| Remote media cache | 9,549 | 0 | This is a cache. Spindle gets remote media from the origin server when a client asks. | Not applicable |
| Signing key | 1 | 1 | The key keeps its Synapse key ID (`ed25519:a_qMqD`) | Not applicable |
| User directory | 50,958 rows | Not applicable | Derived data. Spindle finds users from memberships and profiles. | Not applicable |

Accounts with no known password share the hash of one unguessable password. Nobody holds that password, because sign-in goes through MAS. The E2EE rig's users get their own passwords.

## Rooms

### Rooms that took Synapse's resolved state

For each event, Spindle's log calculates the state from the state of the parents. It does not have the Matrix state resolver (SPEC §9.2). At some events, Synapse resolved a state that the log cannot calculate:

* An event names a parent outside the retained history (`parent outside retained history`).
* A fork changes the same state slot on two branches (`NeedsStateResolution`).
* A parent's state is not in memory any more (`StateNotResident`).
* Synapse's current state is the resolution of several forward extremities. Spindle's current state is the state after its last entry (`head`).

At each of these events, the import seeds the log with the state that Synapse holds for that event in its state groups. Spindle seeds a room that it joins over federation in the same way. The report counts each case per room. After the write, the state of each room agrees with `current_state_events` in every slot.

| Room | Version | Events | From Synapse's state | Reasons |
|---|---|---|---|---|
| `!FjsfNZHkPiXpHlGUCy:reilly.asia` | 10 | 982,883 | 88 | StateNotResident 9, parent outside retained history 79 |
| `!GNPBRmjZKKEGszhMtB:matrix.org` | 10 | 40,055 | 641 | NeedsStateResolution 78, StateNotResident 213, parent outside retained history 350 |
| `!Rgcca1Mbxv5WJUmoQdvjSZwkkaAIbIbc89AwD_n7q8E` | 12 | 5,233 | 10 | NeedsStateResolution 9, parent outside retained history 1 |
| `!RkXKfjpGXIVObpCqOI:element.io` | 10 | 2,888 | 1 | NeedsStateResolution 1 |
| `!dJfsdaSMomJxfpkXMw:matrix.org` | 10 | 1,160 | 9 | NeedsStateResolution 6, StateNotResident 1, head 1, parent outside retained history 1 |
| `!qFKhufhrzYxhwZuHRY:fedoraproject.org` | 10 | 10,111 | 4 | NeedsStateResolution 2, StateNotResident 2 |
| `!sWpnrYUMmaBrlqfRdn:matrix.org` | 10 | 51,736 | 2,617 | NeedsStateResolution 125, StateNotResident 840, head 1, parent outside retained history 1,651 |
| `!vzDE5GnhIhncy8gpyeK4WFPVyeWvIh8JYeM3iqR8RV8` | 12 | 14,873 | 267 | NeedsStateResolution 102, StateNotResident 102, parent outside retained history 63 |

In the other 94 rooms, the log calculated the state of every event. In 16 rooms, the history starts at a retained-history horizon. There, the log starts from the state that Synapse holds at that point.

### Excluded rooms

The build does not support the room version of these 14 rooms. The import reports each one and writes nothing for it. The list of supported versions comes from the build. Thus, when #562 (versions 6 to 9) and #456 (version 1) merge, the same command imports them.

| Room | Version | Synapse events | Local joined members |
|---|---|---|---|
| `!DoHIbNOUnyOcZTnylZ:matrix.org` | 6 | 252 | 1 |
| `!GDJSsXgNxmcxBbBcor:matrix.org` | 9 | 11,161 | 3 |
| `!MOoDVAXQrcYXLtJxBv:frei.chat` | 9 | 199 | 1 |
| `!PYmTIzCXFFOiozouAk:matrix.org` | 9 | 8,265 | 1 |
| `!YBvHYeqGFNgUxmJOOq:fedoraproject.org` | 6 | 15,223 | 1 |
| `!cIIuiddOcRZCzWXaAi:frei.chat` | 9 | 122 | 1 |
| `!gyULLKquuaiOCArbrY:matrix.org` | 1 | 62,861 | 1 |
| `!iMZEhwCvbfeAYUxAjZ:t2l.io` | 6 | 104,445 | 2 |
| `!jXAIqXihWJXJZKnTab:reilly.asia` | 6 | 558 | 1 |
| `!olQSWpshfITIXjtOhK:fedoraproject.org` | 6 | 15,196 | 1 |
| `!qKajKIcEvvlNGMilsv:matrix.org` | 9 | 11,241 | 1 |
| `!twHurYfxLMMQOufslw:fedoraproject.org` | 6 | 23,453 | 1 |
| `!yAfocqXsPDxcabuOMq:frei.chat` | 9 | 104 | 1 |
| `!zVUdYgygGsLfzRPdrW:reilly.asia` | 9 | 16 | 1 |

These rooms hold 253,096 events. The receipts, the alias and the room account data for these rooms wait for the same change.

### Samples

The validation reads 5 events from each imported room, 504 events in total. It selects them with a fixed pseudo-random order (`md5(event_id || 'spindle-563')`), so a second run reads the same events. Spindle serves each one with the same JSON as Synapse, apart from `unsigned`. Where Synapse holds a redaction for the event, Spindle serves the redacted form. There were no mismatches.

Five of the sampled events are:

* `$rvcVYDuWLtzAHmtXfkadOpVr7aBMSejCp2ZeHrJjQlU`
* `$YcP0Icux4JHRhdrUbnPIegpCHjsBP2_NvhqnNe_gTz0`
* `$_MUE2xp2WnA_et00mVjSiH0hDmc_0eIsO0VOwNYFIn4`
* `$FJQFShy1gs2BJrgliNQ3lnh-xk3uOTz0A-m0NsyBKbw`
* `$_cYKvUhgytfxGbBGEEDtmraqxUMcQZg-1erskYkbhH0`

The check also compares the full state of all 102 rooms with `current_state_events`, and the event count of each log with the plan. Both agree for every room.

## Restart

We stopped an earlier run of the same importer on purpose. We deleted its pod with no grace period while it wrote the room with 982,883 events, after 200,000 events. Then the same command continued. It found 7 phases and 14 rooms done in the checkpoint. It skipped the events that the log already held and completed the room. The state and event-count checks agreed after that run too.

The importer writes the checkpoint only after a store sync, so the checkpoint never records more than the store holds.

## E2EE rig on the full target

A second run imported the rig's 4 rooms and users a, b and c from `synapse_dark` into the same store, with `--allow-nonempty` and its own checkpoint (`run.sh rig-import`). That run validated with 0 mismatches. Then `rig.sh verify` (#558) ran against `fi-dark-spindle`:

| User | Recovery | Cross-signed | Readable |
|---|---|---|---|
| a | yes | yes | 89/89 |
| b | yes | yes | 89/89 |
| c | yes | yes | 59/59 |

## Isolation

* `[federation] enabled = false`. `/_matrix/federation/v1/version` and `/_matrix/key/v2/server` answer 404.
* The pods have no resolver (`dnsPolicy: None`, nameserver 127.0.0.1). The import Jobs reach the database through `hostAliases` only.
* There is only a ClusterIP Service, with no Ingress.
* The netwatch sidecar counted 0 outbound connections while the rig ran.
* Nothing in the production namespace changed. A short-lived pod mounted the media PVC read-only with no `fsGroup`, so the kubelet did not change ownership. We deleted the pod after the copy.

## Data that the import does not carry

| Synapse table | Rows | Why |
|---|---|---|
| `access_tokens`, `refresh_tokens` | 141, 0 | MAS owns sessions. The MAS gate on #563 covers them. |
| `user_threepids`, `user_external_ids` | 1, 9 | MAS holds them |
| `user_filters` | 10 | A client uploads its filter again |
| `event_reports` | 10 | Not carried. Export them from the Synapse admin API before cutover. |
| `erased_users` | 1,360 | Spindle has no GDPR erasure flag. These accounts are imported deactivated. |
| `remote_media_cache` | 9,549 | Cache |
| `device_lists_remote_cache`, remote `e2e_cross_signing_keys` | 167,999; 33,931 users | Cache. Spindle gets remote keys over federation. The import brings in a remote key only when a local user's signature needs it, and none did here. |
| `server_keys_json` | 14,380 | Cache |
| `user_ips` | 224 | Not carried |
| `presence_stream` | 10,979 | Presence does not persist |
| `event_push_actions` | 436 | Derived from push rules and receipts |
| `user_directory` | 50,958 | Derived |

## Remaining gaps

* The 14 rooms above wait for #562 and #456.
* Spindle has no state resolver. The 8 rooms in the table above have the state that Synapse resolved. A later fork in those rooms between remote branches is set aside as #225 describes, until a resolver exists.
* The 1,360 erased accounts of the bridge lose their erasure flag.
* This run does not check that a production user can sign in to this target through MAS. That is the MAS gate.
* Spindle gets a remote user's device keys over federation only. A dark target cannot do that. Thus a fresh client sees the keys of a remote user only after cutover.
