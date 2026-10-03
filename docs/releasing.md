# Releasing

ROADMAP.md is the contract: what a `v0.0.x` tag promises (nothing beyond
addressability) and what `v0.1.0` has to show first. This page is the
mechanics.

## When a tag is cut

`.github/workflows/release.yml` cuts tags itself. Every Monday at 06:17
UTC it looks at `main`. If both of the following hold, it tags the commit
with the next patch number (`v0.0.1`, `v0.0.2`, ...). It then releases that
commit in the same run:

- `main` has moved since the last `v*` tag. A week with nothing merged
  produces nothing. A tag names a build, and the same build does not need
  two names.
- CI has finished on that commit and nothing failed. The Rust quality gate
  must have passed. A nightly-only job that CI skipped is fine. A check
  that has not finished means "not yet", and the next Monday asks again.

The decision is `scripts/release-cut.sh`, which prints what it would do
when run from a checkout of `main`; the workflow's `dry_run` input runs
only that. Between Mondays, `workflow_dispatch` cuts one on demand, and
`bump: minor` starts a new line (`v0.1.0`) when ROADMAP.md's evidence for
it exists. Only one release runs at a time, so a dispatch during the
Monday run waits; it does not race the Monday run for the number.

A tag pushed by hand still works, and goes through the same build jobs:

```sh
git tag -a v0.0.1 -m "v0.0.1: an addressable prerelease" origin/main
git push origin v0.0.1
```

Either way the run then:

- builds `spindle` for `x86_64-unknown-linux-gnu` and
  `aarch64-unknown-linux-gnu` from the tagged tree with `--locked`. It
  packages each as a tarball with the licences and the README, plus a
  `.sha256` beside it;
- builds the runtime image (the `Dockerfile` at the root) for `amd64` and
  `arm64` and publishes a manifest at `ghcr.io/tuna-os/spindle:<tag>`;
- writes an SBOM for each tarball and attests it to the tarball. The SBOM
  is SPDX, from `Cargo.lock`, so it names every crate the build pinned;
- signs a provenance attestation for each tarball and each image through
  Sigstore. Each attestation ties to the workflow's own identity. The run
  pushes the image attestations to the registry beside the images;
- creates the GitHub release with the tarballs, the checksums, the SBOMs
  and notes. The notes say what the tag is, then list the titles of the
  pull requests merged since the previous tag. The run marks the release
  as a prerelease for every `v0.*` tag.

The crate version in `Cargo.toml` is not the release version, and a
release does not bump it. The tag is the name, and the binary carries the
commit it was built from.

The release workflow publishes nothing under `latest`. A tag names a build; the next tag
names the next one.

## Checking a build is what it says

A file name proves nothing. The attestation does: it says which workflow,
on which commit, produced the artifact with this digest, and Sigstore's
log says when.

```sh
gh attestation verify spindle-v0.0.1-x86_64-unknown-linux-gnu.tar.gz --repo tuna-os/spindle
gh attestation verify oci://ghcr.io/tuna-os/spindle:v0.0.1 --repo tuna-os/spindle
```

`--repo` is the trust root: the check passes only for attestations signed
by a workflow in this repository. The SBOM beside each tarball is an
SPDX document. The command below checks that the same workflow attested
it, too, to the same tarball:

```sh
gh attestation verify --predicate-type https://spdx.dev/Document
```

## What a tag gives the rest of the project

- Benchmarks can name the Spindle they measured, alongside the Synapse,
  Continuwuity and Tuwunel versions they already name.
- `SECURITY.md`'s "fixed in" can name the first tag that carries a fix.
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
