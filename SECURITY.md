# Security policy

Spindle is a Matrix homeserver: network-facing, multi-tenant, and it
federates with servers it has never met. This policy inherits the
organisation's ([tuna-os/.github/SECURITY.md][org]) and adds what a
homeserver produces that an installer or an image does not.

[org]: https://github.com/tuna-os/.github/blob/main/SECURITY.md

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

1. Open **Security → Report a vulnerability** on this repository and
   describe the affected route or component, a minimal reproduction, the
   impact, and a suggested fix if you have one.
2. If that button is not there, private reporting has not been enabled
   on this repository yet (it is an organisation-level setting, tracked in
   #307). Open an ordinary issue titled `security contact request` with
   **no details in it**. A maintainer will open a private advisory and add
   you to it, and the conversation continues there.

The organisation's fallback (a draft advisory in `tuna-os/tunaos`) needs
write access to that repository, so it is not a route for an outside
reporter; the request issue above is.

## What to report

The classes this codebase produces, most likely first. Two of the first
have already shipped and were found by reading (#257, #258), which is why
#268 exists.

- **Authorization bypass.** Any room read (timeline, state, members,
  context, search, media in a room) served to an account that is not a
  member or that has left; any admin route reachable without the admin
  flag; history visibility not honoured for a former member.
- **Federation.** An `X-Matrix` request accepted with a bad or missing
  signature; an event accepted whose signature, content hash or sender
  domain does not check out, or verified against a key outside its
  validity window; a peer that is not in a room reading or writing it;
  `send_join`/`send_leave` accepting an event other than the one we
  signed.
- **Cross-account disclosure.** One user's account data, devices, keys,
  to-device messages, receipts, pushers or search hits reaching another.
- **Unauthenticated resource exhaustion.** A walk or a write whose cost a
  peer or an unauthenticated client controls without bound: an
  endpoint missing from the rate limiter, per-user or per-peer state
  that grows without a cap, a backfill or key fetch a stranger can make
  us repeat.
- **Authentication.** Access-token or session handling, the built-in
  OIDC provider, delegated authentication, appservice namespace escapes,
  password and registration flows.
- **Outbound requests.** Anything that reaches an internal address
  through URL previews, federated media, key fetches or well-known
  discovery despite `netguard`.

The organisation's classes (supply chain, CI secrets, container images)
apply to this repository's workflows and images as well.

## Disclosure

We aim to acknowledge a report within **5 business days**, as the
organisation's policy says, and to fix on `main` as fast as the fix can
be made sound. We ask for a coordinated window of up to **90 days** from
acknowledgement before details are published, shorter once the fix has
landed.

There are no tagged releases yet (#308), so "fixed in" names a commit on
`main`, and `main` is the only supported line: a deployment tracking
anything older is not supported. When releases exist, the advisory will
name the fixed version as well.

## Scope

In scope: this repository, the server it builds, the container image and
the workflows that build them. Out of scope: the clients and libraries we
depend on (Element, ruma, fjall, axum and the rest); report those to their
maintainers, and tell us if Spindle's use of them is what makes the
problem reachable.

## Finding these yourself

- `scripts/authorization-rule.py` is the CI check that every room read
  in the route table asks who is asking, and `.semgrep/room-authorization.yaml`
  is the shape it looks for.
- `crates/spindle-server/tests/room_read_authorization.rs` and
  `room_route_authorization.rs` are the tests that pin the gates; a new
  bypass should come with a new case there.
- #268 is the standing audit of the authorization surface, and the
  intake counterpart of this document.
