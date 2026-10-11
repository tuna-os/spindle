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

FROM rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
# Extra cargo features, empty for the release image. The Synapse migration
# rehearsal image passes FEATURES=synapse-import.
ARG FEATURES=""
WORKDIR /src
COPY . .
RUN cargo build --release -p spindle-server --bin spindle --locked \
    ${FEATURES:+--features "$FEATURES"}

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
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
