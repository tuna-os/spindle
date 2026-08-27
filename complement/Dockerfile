# Complement image for Spindle.
#
# Satisfies the startup contract (comes up, answers /versions on 8008,
# HEALTHCHECK, TLS on 8448 from the mounted CA) and the test contract:
# complement/allowlist.txt is the ratchet of tests that must pass, and
# scripts/complement.sh runs the suite against this image.
#
# Build from the repository root:
#   docker build -f complement/Dockerfile -t complement-spindle:latest .

FROM rust:1.89-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked --bin spindle

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
