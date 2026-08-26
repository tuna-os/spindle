# Complement image for Spindle.
#
# Satisfies the *startup* contract: the container comes up, answers
# GET /_matrix/client/versions on 8008, and declares a HEALTHCHECK so Complement
# can wait for it. It does not yet satisfy the *test* contract -- see
# complement/README.md for what is missing and complement/allowlist.txt for
# what currently passes, which is nothing.
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
    && apt-get install -y --no-install-recommends ca-certificates openssl curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root at runtime (#11). The entrypoint installs a CA and writes a signed
# certificate, so it needs the paths that involves rather than the container
# being handed root to sidestep the problem.
#
# `update-ca-certificates` writes more than the drop-in directory: it rebuilds
# the bundle in /etc/ssl/certs and reads /etc/ca-certificates.conf. Owning only
# /usr/local/share/ca-certificates leaves it failing on the rebuild, which the
# entrypoint would then report — correctly, and on every single start.
RUN useradd --system --create-home --uid 10001 spindle \
    && mkdir -p /data /certs \
    && chown -R spindle:spindle \
        /data \
        /certs \
        /usr/local/share/ca-certificates \
        /etc/ssl/certs \
        /etc/ca-certificates.conf

COPY --from=build /src/target/release/spindle /usr/local/bin/spindle
COPY complement/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER spindle
WORKDIR /data

EXPOSE 8008 8448

# Complement waits on this before running anything, bounded by
# COMPLEMENT_SPAWN_HS_TIMEOUT_SECS.
HEALTHCHECK --interval=1s --timeout=2s --start-period=1s --retries=60 \
    CMD curl -fsS http://localhost:8008/_matrix/client/versions || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
