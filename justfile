# The project's recipes, so that a task is one command here and the same
# command in CI. `just --list` shows them; `just bench` runs a whole
# competitive sitting from a bare checkout.
#
# Benchmarks are the reason this file exists: a sitting used to be an
# evening of remembering how each competitor is fetched, configured and
# launched. Now it is `just bench-field` (fetch or build every competitor at
# its pin, once), `just bench-sitting` (bring them up, run the rounds, tear
# them down, write the sidecar that says where the numbers came from), and
# `just bench-render` (the site from the committed results).

set shell := ["bash", "-euo", "pipefail", "-c"]

bench_bin := env_var_or_default("BENCH_BIN", justfile_directory() / "tmp/bench-bin")
synapse_venv := env_var_or_default("SYNAPSE_VENV", justfile_directory() / "tmp/synvenv")

default:
    @just --list

# ---- the everyday gates, the way CI runs them ----------------------------

fmt:
    cargo fmt --all
    ruff format scripts

lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    ruff check scripts
    python3 scripts/actions-pinned.py

test *ARGS:
    cargo test --workspace --all-features {{ARGS}}

# The generated pages the quality gate checks against the router.
docs:
    python3 scripts/coverage-dashboard.py
    python3 scripts/readme-numbers.py --write

# ---- benchmarks ----------------------------------------------------------

# Fetch or build every competitor at its pin into BENCH_BIN, and Synapse
# into SYNAPSE_VENV. Idempotent: a binary already at the pin is kept.
bench-field:
    BENCH_BIN="{{bench_bin}}" SYNAPSE_VENV="{{synapse_venv}}" scripts/bench-field.sh

# Spindle itself, release build, the binary every sitting measures.
bench-build:
    cargo build --release -p spindle-server --bin spindle

# Bring every server up on loopback, cold; `just bench-down` stops them.
bench-up:
    BENCH_BIN="{{bench_bin}}" SYNAPSE_VENV="{{synapse_venv}}" scripts/bench-servers.sh up

bench-down:
    BENCH_BIN="{{bench_bin}}" SYNAPSE_VENV="{{synapse_venv}}" scripts/bench-servers.sh down

# One sitting: up, `rounds` rounds of every server in alternating order,
# down, and a sidecar naming the host and the versions. Results land in
# docs/benchmarks/data/<group>.<server>.r<N>.json, which the site reads.
bench-sitting group rounds="3":
    BENCH_BIN="{{bench_bin}}" SYNAPSE_VENV="{{synapse_venv}}" \
      scripts/bench-sitting.sh --group {{group}} --rounds {{rounds}}

# The whole thing from a bare checkout.
bench group rounds="3": bench-field bench-build (bench-sitting group rounds) bench-render

# The site, from the committed results, into site/.
bench-render:
    mkdir -p site
    python3 scripts/render-comparisons.py docs/benchmarks/data site/comparisons.html
    python3 scripts/coverage-dashboard.py --html site/dashboard.html
    @echo "site/comparisons.html"
