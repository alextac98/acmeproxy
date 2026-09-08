FROM docker.io/library/rust:1-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS build
ARG BUILD_PROFILE=release
ARG VCS_REF=unknown
ARG RELEASE_BUILD=false
ENV ACMEPROXY_REVISION=$VCS_REF ACMEPROXY_RELEASE=$RELEASE_BUILD
WORKDIR /build
# Keep Git metadata in the build stage so local Docker builds can identify dirty trees.
# Only the compiled binary and runtime assets are copied to the final image.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --profile "$BUILD_PROFILE" --locked && \
    case "$BUILD_PROFILE" in dev) output_dir=debug ;; release) output_dir=release ;; *) exit 1 ;; esac && \
    cp "/build/target/$output_dir/acmeproxy" /build/acmeproxy-bin

FROM docker.io/library/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends bash ca-certificates curl openssl tar coreutils grep sed && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home acmeproxy && mkdir /config && chown acmeproxy:acmeproxy /config
COPY scripts/install-dnsapi.sh /tmp/install-dnsapi.sh
RUN sh /tmp/install-dnsapi.sh /opt/acme.sh && rm /tmp/install-dnsapi.sh
COPY --from=build /build/acmeproxy-bin /usr/local/bin/acmeproxy
COPY scripts/dev-entrypoint.sh /usr/local/bin/acmeproxy-dev-entrypoint
COPY examples/container.toml /etc/acmeproxy/default.toml
COPY scripts/container-entrypoint.sh /usr/local/bin/acmeproxy-entrypoint
ARG VERSION=unknown
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="ACME Proxy" \
      org.opencontainers.image.source="https://github.com/alextac98/acmeproxy" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF
USER 10001:10001
WORKDIR /config
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/usr/local/bin/acmeproxy-entrypoint"]
CMD []
