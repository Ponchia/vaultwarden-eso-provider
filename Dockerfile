# syntax=docker/dockerfile:1.7

FROM rust:1.99-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627 AS builder

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
