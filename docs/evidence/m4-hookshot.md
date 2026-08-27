# M4 evidence: matrix-hookshot bridges a room on Spindle

The appservice milestone's second exit criterion (#18) names
matrix-hookshot — Element's production bridge for webhooks, GitHub,
GitLab and feeds — alongside the mautrix stack already evidenced in
[m4-appservices.md](m4-appservices.md). This transcript is the real
thing: the **`halfshot/matrix-hookshot` release image**, unmodified,
running its generic-webhooks service against a Spindle over the ordinary
appservice registration, through the full lifecycle a deployed bridge
lives.

## The transcript (2026-08-27)

1. **Registration and startup.** Hookshot loads the registration YAML,
   validates the connection with an MSC2659 ping — Spindle's
   `POST /_matrix/app/v1/ping` answered by the bridge's own HTTP
   listener — provisions its bot user, and reports
   `Bridge is now ready`.
2. **The invite reaches the bridge.** A human creates a room and invites
   `@hookshot:…`; the membership event arrives in a pushed transaction
   and the bot joins by itself. (This found a real bug — see below.)
3. **Commands ride the transaction stream.** Promoted to moderator, the
   bot receives `!hookshot webhook evidence1` via transaction push,
   acknowledges with a ✅ reaction (`m.annotation`), creates an
   admin-room DM, invites the human into it, and hands over the secret
   webhook URL there — hookshot's real flow, exercised end to end.
4. **A ghost speaks.** `POST {url} {"text": "the outside world says hi"}`
   answers 202 and the message lands in the bridged room as
   **`@_webhooks_evidence1:…`**, a virtual user hookshot provisioned in
   its exclusive namespace on the spot.
5. **Restart: state lives in the homeserver.** `docker restart hookshot`
   — it comes back with `Found 1 connections`, rehydrated from the
   connection state events it stored *in Spindle's room state*, and the
   same webhook URL keeps routing.
6. **Retry: nothing is lost while the bridge is down.** With hookshot
   stopped, the human sends a message; Spindle's push loop fails,
   backs off, and — eight seconds after the bridge returns — delivers
   the transaction carrying it. At-least-once, across the peer's
   downtime, from the durable cursor.

## What doing it for real found

Two Spindle bugs, both invisible to Complement and to the mautrix-go
harness, both fixed in this change:

- **The bridge's own invite was never pushed.** Interest was computed
  from the event's sender and the room's *joined* members — and an
  invite is sent by a human to a bot that is not joined yet. A
  membership event *about* an interesting user is now interesting in
  itself (the same rule Synapse applies); hookshot sat invited and
  waiting forever until it was.
- **The trailing-slash state path 404'd.** matrix-bot-sdk spells the
  empty state key as an empty final segment —
  `/state/m.room.provisioned_space/` — which matched neither the
  two-segment nor the three-segment route. Complement's Go client drops
  the segment instead, so no ratcheted test could see it; hookshot
  *crashed* on the unexpected `M_UNRECOGNIZED`. Both spellings now
  resolve to the same handler.

## What this does not show

- GitHub/GitLab/Jira/feeds services — they need reachable third-party
  APIs and OAuth apps; the generic-webhooks service exercises the same
  bridge machinery (registration, push, ghosts, admin rooms, state
  storage) without them.
- Encrypted bridging (`encryption:` in hookshot's config, MSC3202/4190
  paths) — Spindle implements the MSCs and mautrix-level tests cover
  them, but a hookshot run with encryption on has not been done.
- A mautrix *bridge binary* (as opposed to the mautrix-go library run
  in m4-appservices.md) — real mautrix bridges want a remote network
  (WhatsApp, Signal…) on the other side.
