# Deploy Spindle

This page lists the ready-made files under `deploy/`. Choose one of Compose, systemd or Helm. Each one runs a single Spindle process over one store. Read [operations.md](operations.md) for the controls that every deployment needs.

CI checks these files on every change with `scripts/check-deploy.py`. Nobody has yet run each file against a live server in CI. Test your own setup before you rely on it.

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

- `.deb` and `.rpm` packages, and a Nix flake.
- A CI test that starts the Compose stack and registers a user.
