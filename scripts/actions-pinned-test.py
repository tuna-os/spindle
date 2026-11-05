#!/usr/bin/env python3
"""Tests for `actions-pinned.py`, run in CI as a plain script.

No pytest, for the reason complement-check-test.py gives: plain asserts
and a non-zero exit read the same way in a CI log.

Each check is held to the case that made it: the `rounds` input pasted
into bench-sitting.yml's script (#516), the write grants every job of
release.yml inherited (#521, #599), and the Dockerfile bases named by tag
(#652, #687). Each one is also held to what it must let through, so a
check that refused everything would fail here too.

Usage: python3 scripts/actions-pinned-test.py
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "actions_pinned", HERE / "actions-pinned.py"
)
pinned = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pinned
spec.loader.exec_module(pinned)


def test_an_expression_in_a_script_is_refused() -> None:
    # bench-sitting.yml before #516, verbatim.
    workflow = """\
jobs:
  sitting:
    steps:
      - name: The sitting
        env:
          BENCH_RUNNER: github-actions/ubuntu-24.04 (shared runner)
        run: |
          group="ci-$(date -u +%Y%m%d)"
          scripts/bench-sitting.sh --group "$group" --rounds "${{ inputs.rounds || '3' }}" --max-load 4
      - run: echo ${{ github.event.issue.title }}
      - name: Later
        run: |
          # ${{ github.head_ref }} runs even in a comment
          true
"""
    assert pinned.expressions_in_run(workflow) == [
        (9, "${{ inputs.rounds || '3' }}"),
        (10, "${{ github.event.issue.title }}"),
        (13, "${{ github.head_ref }}"),
    ], pinned.expressions_in_run(workflow)


def test_expressions_outside_a_script_pass() -> None:
    # The fix: the value goes through `env:`, and `if:`, `with:` and the
    # job's own keys are expressions GitHub evaluates, not shell source.
    workflow = """\
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
jobs:
  sitting:
    if: ${{ github.event_name != 'push' }}
    steps:
      - name: The sitting
        env:
          ROUNDS: ${{ inputs.rounds || '3' }}
        run: |
          scripts/bench-sitting.sh --rounds "$ROUNDS"
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: ${{ matrix.target }}
      - run: echo "$ROUNDS"
        env:
          ROUNDS: ${{ inputs.rounds }}
"""
    assert pinned.expressions_in_run(workflow) == [], pinned.expressions_in_run(
        workflow
    )


def test_top_level_write_grants_are_refused() -> None:
    # release.yml before #599.
    workflow = """\
on:
  push:
permissions:
  contents: write
  packages: write
  # Sigstore signs the attestations.
  id-token: write
  attestations: write
  checks: read

env:
  CARGO_TERM_COLOR: always
"""
    declared, writes = pinned.top_level_permissions(workflow)
    assert declared
    assert writes == [
        (4, "contents: write"),
        (5, "packages: write"),
        (7, "id-token: write"),
        (8, "attestations: write"),
    ], writes
    assert pinned.top_level_permissions("permissions: write-all\n") == (
        True,
        [(1, "write-all")],
    )


def test_read_only_defaults_and_job_grants_pass() -> None:
    workflow = """\
permissions:
  contents: read
jobs:
  publish:
    permissions:
      contents: write
"""
    assert pinned.top_level_permissions(workflow) == (True, [])
    assert pinned.top_level_permissions("permissions: {}\n") == (True, [])
    # No block at all is the case #521 found: the repository default.
    assert pinned.top_level_permissions(
        "jobs:\n  a:\n    permissions:\n      contents: read\n"
    ) == (
        False,
        [],
    )


def test_an_image_named_by_tag_is_refused() -> None:
    dockerfile = """\
FROM rust:1.99-bookworm AS build
RUN cargo build
FROM debian:bookworm-slim
COPY --from=build /src/target/release/spindle /usr/local/bin/spindle
"""
    assert pinned.unpinned_images("complement/Dockerfile", dockerfile) == [
        (1, "rust:1.99-bookworm"),
        (3, "debian:bookworm-slim"),
    ]
    manifest = """\
      containers:
      - name: synapse
        image: oci.element.io/synapse:v1.156.0
      - image: "busybox:1.36"
"""
    assert pinned.unpinned_images("scripts/rig/k8s/synapse.yaml", manifest) == [
        (3, "oci.element.io/synapse:v1.156.0"),
        (4, "busybox:1.36"),
    ]


def test_digests_stages_and_placeholders_pass() -> None:
    digest = "sha256:" + "0" * 64
    dockerfile = f"""\
FROM --platform=$BUILDPLATFORM rust:1.99-bookworm@{digest} AS build
FROM build AS test
FROM scratch
FROM debian:bookworm-slim@{digest}
"""
    assert pinned.unpinned_images("Dockerfile", dockerfile) == []
    manifest = f"""\
        image: __SPINDLE_IMAGE__
        image: ${{SPINDLE_IMAGE:-complement-spindle:latest}}
        image: oci.element.io/synapse:v1.156.0@{digest}
"""
    assert pinned.unpinned_images("contrib/compose.yml", manifest) == []


def test_the_repository_passes() -> None:
    assert pinned.main() == 0


def main() -> int:
    tests = [
        value for name, value in sorted(globals().items()) if name.startswith("test_")
    ]
    for test in tests:
        test()
        print(f"ok {test.__name__}")
    print(f"actions-pinned-test: {len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
