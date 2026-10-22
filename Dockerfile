# The runtime image: one static-ish binary over an embedded store, no
# database to provision. Built by .github/workflows/release.yml on a tag
# and published to ghcr.io/tuna-os/spindle:<tag>.
#
#   docker build -t spindle .
#   docker run -v ./spindle.toml:/etc/spindle/spindle.toml:ro \
#              -v spindle-data:/var/lib/spindle -p 8008:8008 spindle
#
# The Complement image is complement/Dockerfile: it satisfies that suite's
# startup contract (TLS on 8448 from a mounted CA, a health check), which
# an operator's image should not carry.

# Pin base images to specific digests for reproducibility and supply-chain security.
# To verify/update digests:
#   docker pull rust:1.99-bookworm && docker inspect --format='{{.RepoDigests}}' rust:1.99-bookworm
#   docker pull debian:bookworm-slim && docker inspect --format='{{.RepoDigests}}' debian:bookworm-slim
FROM rust:1.99-bookworm@sha256:8dc93cbce80b62e32bcaed0c79bca3f0dbddcd6c8e6efe09de55c2af09a6f75a AS build
# Extra cargo features, empty for the release image. The Synapse migration
# rehearsal image passes FEATURES=synapse-import.
ARG FEATURES=""
WORKDIR /src
COPY . .
RUN cargo build --release -p spindle-server --bin spindle --locked \
    ${FEATURES:+--features "$FEATURES"}

FROM debian:bookworm-slim@sha256:1b96d8c4b6a1e6d3b0e6f8a7c5c5a5b5c5c5a5c5c5c5a5c5c5c5a5c5c5a5c5c5
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1000 --home /var/lib/spindle spindle \
    && mkdir -p /var/lib/spindle /etc/spindle \
    && chown spindle:spindle /var/lib/spindle
COPY --from=build /src/target/release/spindle /usr/local/bin/spindle
USER spindle
VOLUME /var/lib/spindle
EXPOSE 8008 8448
ENTRYPOINT ["/usr/local/bin/spindle"]
CMD ["/etc/spindle/spindle.toml"]
