# Operating the v0.1 line

Run one Spindle process against each store. The supported release line is
v0.1.x: use its newest patch release; security fixes are developed on main
and included in the next v0.1.x release. No parallel v0.0 backport line is
maintained. A format migration is explicit and can require an offline
maintenance window; see [lifecycle.md](lifecycle.md).

Use [spindle.example.toml](../spindle.example.toml) as the complete setting
reference. Choose the permanent server name before registering accounts.
Keep the client listener on loopback behind a TLS reverse proxy. Keep
federation HTTPS and all outbound private-address exceptions disabled.
Expose only the intended listeners; protect the configuration and signing
key. Container deployments must bind the server to `0.0.0.0:8008` inside the
container and mount the store at `/var/lib/spindle` with UID 1000 write access.
Pin an image tag or digest; there is no `latest` image.

The v0.1 deployment envelope requires the following controls:

- Set `[registration] require_token = true`. Before exposing the server, register a local account
  on loopback, stop the server, run `spindle promote-admin spindle.toml <localpart>`,
  enable token-required registration and restart. Mint registration tokens
  through `POST /_spindle/admin/v1/registration_tokens/new`. Grant tokens only to accounts the operator
  is prepared to support. See [dashboard.md](dashboard.md) for the admin routes.
- Leave `[ratelimit] enabled = true`. Bound ingress connection count,
  requests per source, request body size and timeouts in the reverse proxy.
  Permit the configured media upload size on the upload routes. Do not
  blindly apply a short timeout to Matrix sync long polls.
- Set a process/container memory ceiling and a finite storage quota covering
  the database and media. Size them from the intended workload and measured
  usage. Monitor memory, free disk, health, federation backlog and error
  rates; a quota prevents runaway growth, but reaching it is an outage.
  The CI disk-full drill checks write refusals, not continued availability.
- Take stopped-server database backups and separate media backups. Keep
  both plus configuration and signing keys off the host. Rehearse restore
  into a fresh directory and run `verify-media` before resuming traffic.
  Back up before migration; rollback restores the original backup using
  the old binary. An upgraded directory cannot be opened by an old binary.

[rate-limits.md](rate-limits.md) distinguishes request/processing caps from
account-driven history growth. These deployment controls complement the
server's caps; they are required for the release envelope, not implemented
by the example configuration. Keep the federation listener under the same
resource controls as the client listener.
