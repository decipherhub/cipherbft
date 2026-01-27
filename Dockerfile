# Build stage
FROM rust:1.86-bookworm AS builder

WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

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
