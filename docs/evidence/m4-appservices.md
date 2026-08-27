# M4 evidence: the mautrix appservice stack against Spindle

The appservice milestone's exit criterion was never "the endpoints
exist" — it was that the stack real bridges are built on actually works
here. The harness in `evidence/mautrix-echo/` is that proof: it drives
**mautrix-go's own `appservice` package** (the library every mautrix
bridge — WhatsApp, Telegram, Signal, Discord — is built on, v0.30.0)
against a freshly built Spindle, over real TCP, and asserts the whole
loop.

## What one passing run proves

```
  ok: bot registered as @_bridge_bot:127.0.0.1:28448 through m.login.application_service
  ok: ghost @_bridge_echo:127.0.0.1:28448 provisioned, display name set
  ok: human @alice:127.0.0.1:28448 registered through the ordinary client API
  ok: room !DHAVVERZV:127.0.0.1:28448 created by the bot; ghost and human joined
  ok: bridge received "ping from the human" from @alice:127.0.0.1:28448 via transaction push (hs_token verified by mautrix)
  ok: bridge received m.typing for !DHAVVERZV:127.0.0.1:28448 via MSC2409 ephemeral
  ok: human read "pong from the bridge" from the ghost — the round trip is closed
EVIDENCE: PASS — mautrix-go appservice stack round-trips against Spindle
```

Transcript from 2026-08-27, mautrix-go v0.30.0, Spindle at the commit
that adds this file. Step by step, that is:

1. **Registration works the way bridges register.** The bot intent
   ensures its own account through `m.login.application_service` — the
   UIA-free path — and the ghost provisions through the intent API with
   a profile write under masquerade, exactly how every mautrix puppet
   comes into being.
2. **The transaction push is real.** The human's message arrives at the
   bridge as a pushed `PUT /_matrix/app/v1/transactions/{txnId}`, and it
   is *mautrix* that verifies our `hs_token` before dispatching — a
   wrong token would be rejected by the library, not by our own tests
   grading their own homework.
3. **MSC2409 lands in a real consumer.** The human's typing arrives
   through the `ephemeral` array and mautrix's own gate (`receive_ephemeral`
   in its registration model) lets it through to the handler.
4. **The loop closes.** The ghost answers through the intent API and the
   human reads the reply back through the ordinary client API.

## What the harness deliberately does not cover

End-to-bridge encryption (MSC3202/3983/3984 in anger) needs a bridge
with a crypto store — that is a real-bridge deployment, not a harness.
The unit and integration suites cover our half of those MSCs
(`appservice_transactions.rs`, `appservice_key_proxy.rs`,
`appservice_devices.rs`); this document is about the halves only a
foreign implementation can vouch for.

## Reproducing

```bash
evidence/mautrix-echo/run.sh
```

Needs a Go toolchain (any recent; run recorded with go1.24) and network
access for the mautrix module the first time. Not wired into CI for
exactly that reason: CI proves our code against our tests, this proves
it against someone else's.
