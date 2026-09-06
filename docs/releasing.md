# Releasing

ROADMAP.md is the contract: what a `v0.0.x` tag promises (nothing beyond
addressability) and what `v0.1.0` has to show first. This page is the
mechanics.

## Cutting a tag

A tag is a decision for a person, and one command:

```sh
git tag -a v0.0.1 -m "v0.0.1: an addressable prerelease" origin/main
git push origin v0.0.1
```

`.github/workflows/release.yml` does the rest on the push of any `v*` tag:

- builds `spindle` for `x86_64-unknown-linux-gnu` and
  `aarch64-unknown-linux-gnu` from the tagged tree with `--locked`, and
  packages each as a tarball with the licences and the README, plus a
  `.sha256` beside it;
- builds the runtime image (the `Dockerfile` at the root) for `amd64` and
  `arm64` and publishes a manifest at `ghcr.io/tuna-os/spindle:<tag>`;
- creates the GitHub release with the tarballs, the checksums and notes
  that say what the tag is, marked a prerelease for every `v0.*` tag.

Nothing is published under `latest`. A tag names a build; the next tag
names the next one.

## What a tag gives the rest of the project

- Benchmarks can name the Spindle they measured, alongside the Synapse,
  Continuwuity and Tuwunel versions they already name.
- `SECURITY.md`'s "fixed in" can name the first tag carrying a fix.
- Storage-format changes can say which tag introduced them, with the
  schema version the store already writes in its first byte.

## Running the image

```sh
docker run -v ./spindle.toml:/etc/spindle/spindle.toml:ro \
           -v spindle-data:/var/lib/spindle \
           -p 8008:8008 ghcr.io/tuna-os/spindle:v0.0.1
```

The image runs as an unprivileged user and expects the store under
`/var/lib/spindle`, which `[storage] path` in the mounted config should
name. The Complement image under `complement/` is a different thing: it
satisfies that suite's startup contract and is not for operators.
