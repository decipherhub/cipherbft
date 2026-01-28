# Build stage
FROM rust:1.88-bookworm AS builder

# Install build dependencies for reth-mdbx-sys (bindgen needs libclang)
RUN apt-get update && \
    apt-get install -y --no-install-recommends clang libclang-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Copy vendored dependencies (patched malachite crates for sync fixes):
# - malachitebft-network: OutboundFailure handling for sync retries
# - malachitebft-sync: Automatic height skip when peers lack history
COPY vendor ./vendor

# Build release binary
RUN cargo build --release -p cipherd

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/cipherd /usr/local/bin/

WORKDIR /app

# Expose ports: RPC HTTP, RPC WS, Metrics
EXPOSE 8545 8546 9100

ENTRYPOINT ["cipherd"]
CMD ["start", "--config", "/app/config/node.json"]
