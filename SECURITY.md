# Security policy

Spindle is a Matrix homeserver: network-facing, multi-tenant, and it
federates with servers it has never met. This policy inherits the
organisation's ([tuna-os/.github/SECURITY.md][org]) and adds what a
homeserver produces that an installer or an image does not.

[org]: https://github.com/tuna-os/.github/blob/main/SECURITY.md

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

1. Open **Security → Report a vulnerability** on this repository.
   Include the affected route or component, a minimal reproduction, and the
   impact. Include a suggested fix if you have one.
2. The repository accepts private reports. If the button is unavailable, open
   an ordinary issue titled `security contact request`. Include **no details**
   in it. A maintainer will open a private advisory, add you, and continue the
   conversation there.

Outside reporters cannot use the organisation's fallback draft advisory in
`tuna-os/tunaos` because it needs write access. Use the request issue above.

## What to report

The classes this codebase produces, most likely first. Reviewers found two of
the first flaws after release (#257, #258), which is why #268 exists.

- **Authorization bypass.** Report any room read that serves an account
  without current membership. Room reads include timelines, state, members,
  context, search, and media in a room. Report any admin route without an
  admin-flag check. Report failures to honor history visibility for former
  members.
- **Federation.** Report any accepted `X-Matrix` request with a bad or missing
  signature. Report an event with an invalid signature, content hash, or sender
  domain. Also report verification against a key outside its validity window.
  Report peers that can read or write a room without membership. Report
  `send_join` or `send_leave` if it accepts a different event than Spindle
  signed.
- **Cross-account disclosure.** Report account data, devices, keys, to-device
  messages, receipts, pushers, or search results that reach another user.
- **Unauthenticated resource exhaustion.** Report unbounded work that a peer or
  unauthenticated client controls. Examples include an endpoint absent from the
  rate limiter and per-user or per-peer state without a cap. Also report
  backfill or key fetches that a stranger can force Spindle to repeat.
- **Authentication.** Report flaws in access tokens, sessions, the built-in
  OIDC provider, delegated authentication, appservice namespaces, passwords,
  or registration flows.
- **Outbound requests.** Report internal-address access through URL previews,
  federated media, key fetches, or well-known discovery despite `netguard`.

The organisation's classes (supply chain, CI secrets, container images)
apply to this repository's workflows and images as well.

## Disclosure

We aim to acknowledge a report within **5 business days**, per the
organisation's policy. We aim to commit a sound fix to `main` quickly. We ask
for a coordinated window of up to **90 days** from acknowledgement before
public disclosure. We can shorten the window after the fix lands.

The supported release line is **v0.1.x**; the first release is v0.1.0. Operators
must run the newest patch in that line. Maintainers prepare each fix on `main`
and add it to the next v0.1.x release. Advisories name the fix commit and first
release with it. Older v0.0.x builds receive no backports.

The line remains a prerelease, and storage migrations can need downtime.
`docs/lifecycle.md` documents backup-based rollback.

## Scope

In scope: this repository, its server, its container image, and its build
workflows. Clients and dependent libraries are out of scope. Examples include
Element, ruma, fjall, and axum. Report those flaws to their maintainers. Tell us
if Spindle's use of them makes a problem reachable.

## Finding these yourself

- `scripts/authorization-rule.py` checks that each room-read route identifies
  the requester. `.semgrep/room-authorization.yaml` defines the required
  pattern.
- `crates/spindle-server/tests/room_read_authorization.rs` and
  `room_route_authorization.rs` contain the tests that pin the gates. Add a test
  case there for each new bypass.
- Issue #268 tracks the authorization audit and is this document's intake
  counterpart.
