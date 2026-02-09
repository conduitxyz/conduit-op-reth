#
# Base container (with sccache and cargo-chef)
#
ARG FEATURES
ARG BUILD_PROFILE=maxperf

FROM rust:1.92 AS base
ARG TARGETPLATFORM

RUN apt-get update \
    && apt-get install -y clang libclang-dev libtss2-dev zlib1g-dev

RUN rustup component add clippy rustfmt

RUN set -eux; \
    case "$TARGETPLATFORM" in \
      "linux/amd64")  ARCH_TAG="x86_64-unknown-linux-musl" ;; \
      "linux/arm64")  ARCH_TAG="aarch64-unknown-linux-musl" ;; \
      *) \
        echo "Unsupported platform: $TARGETPLATFORM"; \
        exit 1 \
        ;; \
    esac; \
    wget -O /tmp/sccache.tar.gz \
      "https://github.com/mozilla/sccache/releases/download/v0.8.2/sccache-v0.8.2-${ARCH_TAG}.tar.gz"; \
    tar -xf /tmp/sccache.tar.gz -C /tmp; \
    mv /tmp/sccache-v0.8.2-${ARCH_TAG}/sccache /usr/local/bin/sccache; \
    chmod +x /usr/local/bin/sccache; \
    rm -rf /tmp/sccache.tar.gz /tmp/sccache-v0.8.2-${ARCH_TAG}

RUN cargo install cargo-chef --version ^0.1

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTC_WRAPPER=sccache
ENV SCCACHE_DIR=/sccache

#
# Planner container
#
FROM base AS planner
WORKDIR /app
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo chef prepare --recipe-path recipe.json

#
# Builder container
#
FROM base AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
ARG BUILD_PROFILE=maxperf

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo chef cook --profile $BUILD_PROFILE --recipe-path recipe.json
COPY . .

FROM builder AS conduit-op-reth-build
ARG FEATURES
ARG BUILD_PROFILE=maxperf

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo build --profile $BUILD_PROFILE --features="$FEATURES" --package=conduit-op-reth

#
# Runtime container
#
FROM debian:13-slim AS conduit-op-reth-runtime
RUN apt update && apt install -y curl jq && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ARG BUILD_PROFILE=maxperf
COPY --from=conduit-op-reth-build /app/target/$BUILD_PROFILE/conduit-op-reth /app/conduit-op-reth
RUN ln -s /app/conduit-op-reth /usr/local/bin/op-reth
ENTRYPOINT ["/app/conduit-op-reth"]
