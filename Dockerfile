# syntax=docker/dockerfile:1.7

FROM rust:1.98-alpine@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS builder

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
