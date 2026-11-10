# Media moderation tools

This note lists the media calls that Spindle answers for tools such as Draupnir and Meowlnir.
It lists routes, not tool behaviour. Neither tool is run against Spindle in CI.
Only synadm is (`contrib/synadm/run.sh`).

Spindle answers every route below under `/_spindle/admin/v1` and under the `/_synapse/admin/v1` alias.
The caller must be a server admin. Spindle writes each change to the audit log.

## Served

- `POST /media/quarantine/{server_name}/{media_id}` quarantines one item. Remote items are held even when uncached.
- `POST /media/unquarantine/{server_name}/{media_id}` releases one item.
- `POST /user/{user_id}/media/quarantine` quarantines every upload of a local user.
- `POST /room/{room_id}/media/quarantine` quarantines every item the room's events point at.
- `POST /media/protect/{media_id}` and `POST /media/unprotect/{media_id}` protect a local upload, as Synapse does.
- `POST /media/protect/{server_name}/{media_id}` and the matching `unprotect` route are a Spindle extension. They protect a cached remote item.
- `POST /purge_media_cache?before_ts=` deletes remote media that Spindle cached before the timestamp.
- `GET /media/{server_name}/{media_id}`, `DELETE /media/{server_name}/{media_id}`, `GET /users/{user_id}/media` and `DELETE /users/{user_id}/media` are also routes that Spindle answers.

## Not served

- Spindle has no route for `POST /media/delete` (delete local media by age or size).
- Spindle has no route for `GET /room/{room_id}/media` (list the media of a room).
- `last_access_ts` is always `null`. Spindle does not record reads.

## What the flags mean

A quarantined item answers 404 on download and thumbnail. Spindle does not send it over federation. Its record and bytes stay as evidence.

A protected item is still served. Purge, `remote_retention_days` and the cache caps never remove it.

Bulk quarantine by user or room skips a protected item, as Synapse does (`safe_from_quarantine`). If you quarantine a protected item by name, the quarantine still holds.

Automatic cleanup never removes a quarantined or protected item. An explicit admin `DELETE` still removes either.
