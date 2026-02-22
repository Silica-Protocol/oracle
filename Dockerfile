FROM rust:1.75 AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build dependencies first (for caching)
RUN mkdir -p src && \
    touch src/lib.rs && \
    cargo build --release --locked

# Build the binary
RUN cargo build --release --locked

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/silica-oracle /app/

# Copy config
COPY config.json ./

# Create data directory
RUN mkdir -p /app/data && chown -R app:app /app

USER app

EXPOSE 8765

ENTRYPOINT ["/app/silica-oracle"]
