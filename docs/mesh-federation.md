# Federating with a Bluetooth mesh: what Spindle answers, and what a venue needs

The IndiaFOSS Companion project runs Matrix rooms on phones with no
internet: Neutrino (Element's P2P homeserver) over iroh over Bluetooth LE,
one homeserver per phone, federating phone to phone. Their RFC asks whether
those rooms can reach the rest of Matrix through a Spindle hosted for the
conference, so that people at home and people at the venue share the same
rooms, and so that a phone coming back online catches up from the Spindle.
This page answers the RFC's questions from the code as it stands, and says
what the `spindle-hub-p2p` branch adds. It is written for the mesh side as
much as for operators.

The design decision the RFC makes -- plain federation, no portal bridge --
is the right one for Spindle too: this server relays ciphertext and key
material and never holds plaintext, and every endpoint that needs is served
(client-server and federation E2EE, to-device delivery, device-list EDUs,
authenticated media).

## Room version

SPEC.md describes a Linearized Matrix room version and the MSC3995 hub
protocol. **Neither is implemented.** The server creates and accepts room
versions 11 and 12, and federates with them the ordinary way: every event is
appended in arrival order to a linear log, forks are classified and counted,
and a contested same-slot fork is set aside rather than resolved
(docs/divergence.md). The RFC's first option -- Spindle as a linearized
hub, Neutrino as a linearized participant -- therefore needs the hub protocol
built first, on both sides, and that is weeks of work with an MSC that is
itself still moving.

The RFC's second option federates today: **room version 12 on the Neutrino
side, with signing.** Neutrino's MSC4242 rooms are built on v12's auth
rules, so the distance is state resolution on the phone, which is what
MSC4242 exists to avoid. That cost falls on the phone and not on Spindle,
and it is bounded by the room: a conference session room is small and
short-lived.

## Signatures

Every inbound PDU goes through ruma's `verify_event` against the origin's
fetched key document. A content hash that does not match is redacted, as
the spec says; a missing or bad signature is refused; there is no mode in
which unsigned history is accepted, and adding one would break the property
the design rests on -- ordering is trusted, content never is (SPEC.md G6).

So the answer to "may the older mesh events be unsigned" is no: **the mesh
must sign from the first event.** That is cheaper than it sounds. An iroh
node key is an ed25519 key, which is exactly what a Matrix signing key is,
so the node key can be the server's signing key with no second secret to
manage; and a peer's `old_verify_keys` are honoured until their `expired_ts`
(#300), so a phone that rotates its key later does not orphan what it signed
before.

## Reachability

An outbound event is a row in a per-destination outbox, and **rows are
deleted only when the destination acknowledges the transaction**; a peer
that is dark for a day loses nothing. What the code did until this branch
was retry every unreachable peer on a doubling backoff capped at 64 times
`retry_base_ms` -- about once a minute -- which is right for a server that
has fallen over and wrong for a phone that has walked out of range.

`[federation] peers` (below) gives a peer its own `max_backoff_ms`. A peer
listed with an hour is tried once an hour while it is dark and immediately
on the next pass once it answers; a transaction carries up to fifty events,
so a returning peer is caught up in a few round trips.

## Server names and keys

A federation peer is found by its name: **delegation (`.well-known`, SRV)
is not resolved; the name is the host.** A Neutrino server named by its
node key, 64 hex characters, has no host to be found at, and a venue
gateway on a LAN has no DNS. `[federation] peers` lists such a peer with the
URL its requests go to:

```toml
[federation]
peers = { "a1b2…f0a1b2" = { url = "http://10.20.0.5:8008", max_backoff_ms = 3600000 } }
```

A listed URL is vetted like a resolved name: a literal inside address needs
the range in `allow_internal`, and a hostname is judged by the resolver
when the connection is made. `http` is permitted for a listed peer without
turning `insecure_http` on for everyone, because the operator has named one
host they run. The peer's key document must be self-signed by the key it
advertises, which is already the rule; a node key that signs its own key
document satisfies it.

## Media

Spindle fetches federated media from the origin's authenticated endpoint
and, if that is not served, from the legacy public one. A peer that caps
what it serves -- Neutrino at 256 KiB -- answers `413 M_TOO_LARGE`, and on
this branch **that answer is final**: it is returned to the client as the
peer's refusal, and the legacy endpoint is not asked to repeat it. Nothing
Spindle fetches from a peer is larger than the peer chose to serve, so no
per-peer size limit is needed on this side; uploads to Spindle keep their
own cap (`media::MAX_UPLOAD`).

## The 3,000-attendee venue: topology, not code

Spindle fans every event out to every server with a live member in the
room. With one homeserver per phone, one message in the venue room becomes
one HTTPS transaction per phone, most of them to phones that are out of
range at that moment; three thousand outboxes backing off is not a
homeserver, it is a port scanner. The push and sync sides are fine at that
scale -- three thousand accounts and three thousand long-poll waiters are
what a single node serves today -- the federation fan-out is not.

The answer is the one mesh networks already use: **a handful of venue
gateways are the Spindle's only federation peers.** A gateway is a
Neutrino node with the venue's uplink (a laptop or a small computer at the
registration desk), listed in `[federation] peers` with a patient backoff.
Phones federate over the mesh with each other and with the gateways;
gateways federate with the Spindle. The Spindle then sees three to five
peers, each of which it can wait hours for, and the mesh sees the Spindle's
rooms as the copy a gateway carries. Whether Bluetooth gossip itself scales
to three thousand nodes is the mesh's question, and the harder one.

## What this branch does not do

- The MSC3995 hub protocol. SPEC.md §12 is the design; nothing implements
  it. Worth building only if Neutrino commits to Linearized Matrix.
- Delegation. A peer whose name is a real hostname with `.well-known` or SRV
  delegation is still reached at the name; `peers` is the explicit override,
  not a resolver.
- Anything on the Neutrino side. The RFC's patches (E2EE surface, to-device,
  media) are theirs to carry; v12 with signing is the convergence this page
  asks for.
