# Complement image for Spindle.
#
# Satisfies the startup contract (comes up, answers /versions on 8008,
# HEALTHCHECK, TLS on 8448 from the mounted CA) and the test contract:
# complement/allowlist.txt is the ratchet of tests that must pass, and
# scripts/complement.sh runs the suite against this image.
#
# Build from the repository root:
#   docker build -f complement/Dockerfile -t complement-spindle:latest .

FROM rust:1.90-bookworm AS build
WORKDIR /src

# The dependency layer: manifests only, with placeholder sources, so the
# workspace's dependency graph compiles once and stays cached until
# Cargo.lock moves. Every CI run changes our own code and nothing else,
# and without this split that recompiles everything — measured at 2m11s
# for a one-line edit, against 22s with it.
#
# Adding a crate without adding it here is not a correctness problem: the
# placeholder build simply will not cover it and the real build compiles
# it from scratch. The failure mode is a slower build, not a wrong one.
COPY Cargo.toml Cargo.lock ./
COPY crates/spindle-core/Cargo.toml crates/spindle-core/
COPY crates/spindle-store/Cargo.toml crates/spindle-store/
COPY crates/spindle-server/Cargo.toml crates/spindle-server/
RUN mkdir -p crates/spindle-core/src crates/spindle-store/src \
             crates/spindle-server/src crates/spindle-core/benches \
    && touch crates/spindle-core/src/lib.rs \
             crates/spindle-store/src/lib.rs \
             crates/spindle-server/src/lib.rs \
    && echo 'fn main() {}' > crates/spindle-server/src/main.rs \
    # spindle-core declares its benches explicitly, and cargo refuses to
    # parse a manifest whose named target has no file — even for a build
    # that would never compile them.
    && for bench in fork_window state_snapshot state_res_comparison; do \
         echo 'fn main() {}' > "crates/spindle-core/benches/$bench.rs"; \
       done \
    && cargo build --release --locked --bin spindle

# The real sources. `touch` because cargo decides freshness by mtime, and
# a checkout can hand it files older than the placeholder artefacts —
# which would leave the placeholder binary in the image, and a server
# that does nothing is a very confusing Complement failure.
COPY crates ./crates
RUN find crates -name '*.rs' -exec touch {} + \
    && cargo build --release --locked --bin spindle

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates openssl curl util-linux \
    && rm -rf /var/lib/apt/lists/*

# Non-root at runtime (#11) — the *server*, not the setup.
#
# The entrypoint has to read /complement/ca/ca.key, and Complement writes that
# key the way OpenSSL writes any private key: mode 0600, owned by whoever
# generated it. A container user that is not that owner cannot read it, and no
# amount of chowning inside the image changes a file that arrives on a mount.
# So setup runs as root and the entrypoint drops to this user before exec'ing
# the server, which is the part that stays up and takes traffic.
RUN useradd --system --create-home --uid 10001 spindle \
    && mkdir -p /data /certs \
    && chown -R spindle:spindle /data /certs

COPY --from=build /src/target/release/spindle /usr/local/bin/spindle
COPY complement/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# No `USER` directive: the entrypoint needs root for the CA, and drops to
# uid 10001 itself. PID 1 is therefore the server running unprivileged.
WORKDIR /data

EXPOSE 8008 8448

# Complement waits on this before running anything, bounded by
# COMPLEMENT_SPAWN_HS_TIMEOUT_SECS.
HEALTHCHECK --interval=1s --timeout=2s --start-period=1s --retries=60 \
    CMD curl -fsS http://localhost:8008/_matrix/client/versions || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
