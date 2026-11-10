# Media moderation tools

This note says which media admin calls Spindle serves for moderation tools such as Draupnir and Meowlnir.
It lists routes, not tool behaviour. Neither tool is run against Spindle in CI.
Only synadm is (`contrib/synadm/run.sh`).

Every route below is served under `/_spindle/admin/v1` and under the `/_synapse/admin/v1` alias.
The caller must be a server admin. Each change is written to the audit log.

## Served

- `POST /media/quarantine/{server_name}/{media_id}` quarantines one item. Remote items are held even when uncached.
- `POST /media/unquarantine/{server_name}/{media_id}` releases one item.
- `POST /user/{user_id}/media/quarantine` quarantines every upload of a local user.
- `POST /room/{room_id}/media/quarantine` quarantines every item the room's events point at.
- `POST /media/protect/{media_id}` and `POST /media/unprotect/{media_id}` protect a local upload, as Synapse does.
- `POST /media/protect/{server_name}/{media_id}` and the matching `unprotect` route are a Spindle extension. They protect a cached remote item.
- `POST /purge_media_cache?before_ts=` deletes cached remote media cached before the timestamp.
- `GET /media/{server_name}/{media_id}`, `DELETE /media/{server_name}/{media_id}`, `GET /users/{user_id}/media` and `DELETE /users/{user_id}/media` are served too.

## Not served

- `POST /media/delete` (delete local media by age or size) is not routed.
- `GET /room/{room_id}/media` (list a room's media) is not routed.
- `last_access_ts` is always `null`. Spindle does not record reads.

## What the flags mean

A quarantined item answers 404 on download and thumbnail and is not sent over federation. Its record and bytes stay as evidence.
A protected item is still served. Purge, `remote_retention_days` and the cache caps never remove it.
Bulk quarantine by user or room skips a protected item, as Synapse does (`safe_from_quarantine`).
Quarantining a protected item by name still holds it.
Automatic cleanup removes neither a quarantined nor a protected item. An explicit admin `DELETE` still removes either.
