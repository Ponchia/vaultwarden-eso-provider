# syntax=docker/dockerfile:1.7

FROM rust:1.95-alpine@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2 AS builder

WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN apk add --no-cache musl-dev

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/target \
    cargo build --locked --release -p vaultwarden-eso-provider \
    && cp /workspace/target/release/vaultwarden-eso-provider /usr/local/bin/vaultwarden-eso-provider

FROM scratch AS runtime

COPY --from=builder /usr/local/bin/vaultwarden-eso-provider /usr/local/bin/vaultwarden-eso-provider

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/vaultwarden-eso-provider", "--healthcheck-url", "http://127.0.0.1:8080/livez"]

ENTRYPOINT ["/usr/local/bin/vaultwarden-eso-provider"]
