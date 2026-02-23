# Test runner Dockerfile for Oracle E2E tests
# Builds the oracle binary and runs pytest tests

FROM rust:1.83-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files first for caching
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build release binary
RUN cargo build --release --bin silica-oracle

# Runtime stage
FROM python:3.12-slim-bookworm

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install TigerBeetle client library
RUN curl -Lo /usr/local/bin/tigerbeetle \
    https://github.com/tigerbeetle/tigerbeetle/releases/download/2024.08.27/tigerbeetle-linux-x86_64 \
    && chmod +x /usr/local/bin/tigerbeetle

# Copy built binary from builder
COPY --from=builder /app/target/release/silica-oracle /usr/local/bin/

# Install Python test dependencies
COPY tests/requirements.txt ./tests/
RUN pip install --no-cache-dir -r tests/requirements.txt

# Copy test files
COPY tests ./tests
COPY pyproject.toml ./

# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["pytest", "tests/e2e/", "-v", "--tb=short"]
