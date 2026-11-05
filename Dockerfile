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

# Both bases are pinned by digest as well as tag (#652, #687). A tag is a
# pointer the registry can move, so without the digest a release could
# ship a compiler or runtime nobody reviewed, with no diff here to show
# it. The tag stays for the reader and for Dependabot, which rewrites the
# tag and the digest together. complement/Dockerfile pins the same two.
FROM rust:1.99-bookworm@sha256:7085845219c18e7c5b1f34ed9ce89b84f822f2e3d54a02774cedc996ac0f304f AS build
# Extra cargo features, empty for the release image. The Synapse migration
# rehearsal image passes FEATURES=synapse-import.
ARG FEATURES=""
WORKDIR /src
COPY . .
RUN cargo build --release -p spindle-server --bin spindle --locked \
    ${FEATURES:+--features "$FEATURES"}

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
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
