FROM docker.io/library/rust:1-bookworm AS build
ARG BUILD_PROFILE=release
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY web ./web
COPY docs/providers.json ./docs/providers.json
COPY scripts ./scripts
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --profile "$BUILD_PROFILE" --locked && \
    case "$BUILD_PROFILE" in dev) output_dir=debug ;; release) output_dir=release ;; *) exit 1 ;; esac && \
    cp "/build/target/$output_dir/acmeproxy" /build/acmeproxy-bin

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash ca-certificates curl openssl tar coreutils grep sed && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home acmeproxy && mkdir /config && chown acmeproxy:acmeproxy /config
COPY scripts/install-dnsapi.sh /tmp/install-dnsapi.sh
RUN sh /tmp/install-dnsapi.sh /opt/acme.sh && rm /tmp/install-dnsapi.sh
COPY --from=build /build/acmeproxy-bin /usr/local/bin/acmeproxy
COPY scripts/dev-entrypoint.sh /usr/local/bin/acmeproxy-dev-entrypoint
COPY examples/container.toml /etc/acmeproxy/default.toml
USER 10001:10001
WORKDIR /config
EXPOSE 8080
ENTRYPOINT ["acmeproxy"]
CMD ["serve", "--config-dir", "/config"]
