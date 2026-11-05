# Operating the v0.1 line

Run one Spindle process against each store. The supported release line is
v0.1.x. Use its newest patch release. Maintainers develop security fixes on main
and release them in the next v0.1.x patch. There are no v0.0 backports.
A format migration can need an offline maintenance window; see [lifecycle.md](lifecycle.md).

Use [spindle.example.toml](../spindle.example.toml) as the complete setting
reference. Choose the permanent server name before you register accounts.
Keep the client listener on loopback behind a TLS reverse proxy. Use
federation HTTPS. Disable exceptions for outbound access to private addresses.
Expose only the intended listeners; protect the configuration and signature
key.

Container deployments must bind the server to `0.0.0.0:8008` inside the
container and mount the store at `/var/lib/spindle` with UID 1000 write access.
Pin an image tag or digest; there is no `latest` image.

The v0.1 deployment envelope needs these controls:

- Set `[registration] require_token = true`. Before you expose the server, register a local account
  on loopback, stop the server, run `spindle promote-admin spindle.toml <localpart>`,
  enable token-required registration and restart. Mint registration tokens
  through `POST /_spindle/admin/v1/registration_tokens/new`. Grant tokens only to accounts the operator
  can support. See [dashboard.md](dashboard.md) for the admin routes.
- Leave `[ratelimit] enabled = true`. Limit the number of ingress connections,
  requests per source, request body size and timeouts in the reverse proxy.
  Allow uploads up to the configured size. Do not
  blindly apply a short timeout to long polls for Matrix sync.
  The per-account write budgets (sends, joins, invites, room creation,
  uploads) default to Synapse's numbers; a bot that is not an appservice
  will meet them, so give it a registration with `rate_limited: false`,
  make it an admin, or raise the budget in `[ratelimit]`. Setting
  `[media] max_bytes_per_user` bounds what each account's uploads may hold.
- Set a process/container memory ceiling and a finite storage quota for
  the database and media. Size them from the intended workload and measured
  usage. Monitor memory, free disk, health, federation backlog and errors.
  A quota prevents runaway growth, but a full disk causes an outage.
  The disk-full drill in CI checks write refusals. It does not prove continued availability.
- Take stopped-server database backups and separate media backups. Keep
  both plus configuration and signature keys off the host. Rehearse restore
  into a fresh directory and run `verify-media` before you resume traffic.
  Back up before migration; rollback restores the original backup using
  the old binary. An old binary refuses an upgraded directory.
- Only `spindle gc <config>` frees the disk that the state trie no longer
  uses. Run it with the server stopped. `--dry-run` reports what it can free.
  No online collector exists. See [lifecycle.md](lifecycle.md).

[rate-limits.md](rate-limits.md) distinguishes caps on requests and work from
account-driven history growth. These deployment controls complement the
server's caps; they are required for the release envelope, not implemented
by the example configuration. Keep the federation listener under the same
resource controls as the client listener.
