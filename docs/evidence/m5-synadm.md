# M5 evidence: synadm drives Spindle's admin API

The admin API (#83) carries a `/_synapse/admin` alias so that tooling
written for Synapse works without a patch. This is that claim tested
with the tool itself: **synadm 0.49.2**, the Synapse admin CLI,
configured the way its own `synadm config` writes its file and pointed
at a Spindle, run by `contrib/synadm/run.sh` on every pull request.

## The transcript (2026-09-06)

Sixteen commands, each run as an operator runs it (`--batch -o json`)
and checked for the field the operator would read:

| Command | Endpoint synadm calls | Answer |
|---|---|---|
| `version` | `GET /v1/server_version` | `spindle 0.1.0` |
| `user list`, `user list -d` | `GET /v2/users` | the users, deactivated ones on request |
| `user details` | `GET /v2/users/{id}` | name, admin flag, deactivated |
| `user membership --ids` | `GET /v1/users/{id}/joined_rooms` | the rooms |
| `user whois` | `GET /v1/whois/{id}` | the sessions |
| `user modify` (create) | `PUT /v2/users/{id}` | the account, display name set |
| `user password --no-logout` | `POST /v1/reset_password/{id}` | ok |
| `user deactivate` | `POST /v1/deactivate/{id}` | ok, and `user list -d` shows it |
| `room list`, `room details`, `room members`, `room state` | `GET /v1/rooms…` | the room, its members, its state |
| `room make-admin` | `POST /v1/rooms/{id}/make_room_admin` | a real power-levels event |
| `history purge --before-days 0` | `POST /v1/purge_history/{id}` | bodies gone, spine kept |
| `room delete --v1` | `DELETE /v1/rooms/{id}` | the room gone |

```
synadm against Spindle: 16 ok, 0 failed, 0 not served
```

## What it took

Synapse spells some of these differently from `/_spindle/admin/v1`, so
`admin.rs` serves those spellings on the alias: the v2 user endpoints
(Synapse retired its v1 ones), `deactivate` and `reset_password` with
the verb before the target, `purge_history` likewise, and
`delete_devices`, which takes a list where this API takes one device
per `DELETE`. Same handlers, same audit records.

## What this does not show

- `user membership` with aliases (synadm's default) resolves each room's
  aliases through the client API as the admin, who is not a member, and
  this server answers a non-member's alias read with 403 where Synapse
  lets a server admin through. The rig passes `--ids`; the gap is named
  here rather than papered over.
- Registration tokens, server notices, media quarantine and the
  federation-destination commands: their endpoints are unrouted on
  purpose (#83 says why), and synadm reports a 404 for each, which the
  rig lists as "not served" rather than a failure.
- The async room delete (v2) and its status endpoints.
