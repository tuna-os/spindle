# M5 evidence: synadm drives Spindle's admin API

The admin API (#83) carries a `/_synapse/admin` alias so that tooling
written for Synapse works without a patch. This page tests that claim
with the tool itself: **synadm 0.49.2**, the Synapse admin CLI. Its
configuration is the file that its own `synadm config` writes, pointed
at a Spindle. `contrib/synadm/run.sh` runs it on every pull request.

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

Synapse spells some of these differently from `/_spindle/admin/v1`.
So `admin.rs` serves those spellings on the alias:

- the v2 user endpoints (Synapse retired its v1 ones);
- `deactivate` and `reset_password`, with the verb before the target;
- `purge_history`, also with the verb first;
- `delete_devices`, which takes a list where this API takes one device
  per `DELETE`.

Same handlers, same audit records.

## What this does not show

- `user membership` with aliases (synadm's default) resolves the aliases
  of each room through the client API, as the admin. The admin is not a
  member. This server answers an alias read from a non-member with 403.
  Synapse lets a server admin through. The rig passes `--ids`; this page
  names the gap and does not paper over it.
- Registration tokens, server notices, media quarantine and the
  federation-destination commands. Spindle does not route their endpoints,
  on purpose (#83 says why). synadm reports a 404 for each. The rig lists
  each as "not served", not as a failure.
- The async room delete (v2) and its status endpoints.
