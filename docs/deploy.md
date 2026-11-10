# Deploy Spindle

This page lists the ready-made files under `deploy/`. Choose one of Compose, systemd or Helm. Each one runs a single Spindle process over one store. Read [operations.md](operations.md) for the controls that every deployment needs.

CI checks these files on every change with `scripts/check-deploy.py`. A second CI job, `scripts/deploy-smoke.sh`, builds the image, starts the Compose file's Spindle service and registers a user. It then logs in, creates a room and sends a message. It does not start Caddy, and CI has not run the systemd unit or the Helm chart against a live server. Test your own setup before you rely on it.

Run the smoke test yourself with `scripts/deploy-smoke.sh`. It needs Docker, `curl` and `jq`. Set `SPINDLE_IMAGE` to test a published image instead of a local build.

## Before you start

Choose the permanent server name first. It goes into every user ID and room ID. You cannot change it later.

Pin a release tag and an image digest. Take both from the release notes. There is no `latest` image.

The release tarballs and the image include the importers `spindle import-mas` and `spindle import-synapse`.

## Compose with Caddy

Use `deploy/compose/`. It runs Spindle and Caddy. Caddy gets the TLS certificate and answers `/.well-known/matrix/server`.

1. Copy `.env.example` to `.env`. Set `SPINDLE_IMAGE` and `SPINDLE_DOMAIN`.
2. Edit `spindle.toml`. Set `server.name` and `public_base_url` to your host.
3. Run `docker compose up -d`.

Only Caddy publishes ports 80 and 443. Spindle has no published port.

The first account needs a local step. Follow the admin steps in [operations.md](operations.md). Then keep `require_token = true`.

### Element Call

Add LiveKit with a second file. This uses the built-in JWT service from [matrix-rtc.md](matrix-rtc.md), option A.

1. In `livekit.yaml` and `spindle-rtc.toml`, replace `CHANGE_ME_TO_A_LONG_RANDOM_SECRET`. Use the same value in both files.
2. In `spindle-rtc.toml`, set `url` to your `lk.` host.
3. Add a DNS record for `lk.` plus your domain.
4. Open `7881/tcp` and `7882/udp` in the firewall.
5. Run `docker compose -f compose.yaml -f compose.livekit.yaml up -d`.

## systemd

The release tarball has `spindle`, `spindle.example.toml` and `spindle.service`. The install steps are at the top of the unit.

The unit uses `DynamicUser` and `StateDirectory=spindle`. The store lives in `/var/lib/spindle`. Set `[storage] path = "/var/lib/spindle"` in the config.

The config stays readable by root only. systemd gives the service a copy.

The unit has the usual sandbox settings. Nobody has yet run it on a live host in CI. If your setup needs more access, relax one setting at a time.

### Packages

Each release may also carry a `.deb` and an `.rpm` for amd64 and arm64. They hold the binary in `/usr/bin/spindle`, the unit, the licences and the example config as `/etc/spindle/spindle.toml`. Your edits to the config survive an upgrade.

The unit uses `DynamicUser`, so the package creates no account. The package does not enable the service. Edit the config, then run `systemctl enable --now spindle`.

The release job builds the packages apart from the tarballs and the image. If that job fails, the release ships without them. Verify a package with `gh attestation verify` like a tarball.

## Kubernetes with Helm

Use `deploy/helm/spindle`. It makes one StatefulSet replica, a volume claim, a Service and optional Ingress and ServiceMonitor objects.

```sh
helm install spindle deploy/helm/spindle \
  --set image.tag=v0.1.0 \
  --set image.digest=sha256:... \
  --set config.serverName=example.org \
  --set config.publicBaseUrl=https://matrix.example.org
```

The readiness probe uses `/ready`. The liveness probe uses `/health`.

Do not scale the StatefulSet. Two processes must not open one store.

If the config holds secrets, put it in a Secret and set `config.existingSecret`. The key must be `spindle.toml`.

Set `metrics.enabled` for the metrics port, and `metrics.serviceMonitor.enabled` if you run the Prometheus Operator. The plain manifests are in `deploy/kubernetes/`.

## Reverse proxies

`deploy/proxy/` has a Caddy file and an nginx file for a proxy on the same host as Spindle.

Both do four things:

- They serve `/.well-known/matrix/server` with `host:443`. Spindle does not name a port there, and peers would try port 8448.
- They set no short timeout on `/sync`. It is a long poll.
- They allow uploads up to `[media] max_upload_bytes`.
- They send events on without buffering.

Federation also needs a valid certificate on the public host name.

## What is not here

- A Nix flake.
- A CI test of the systemd unit and the Helm chart on a live host.
- Package repositories. The packages are release assets only.
