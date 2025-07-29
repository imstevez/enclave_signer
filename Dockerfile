# Builder
FROM rust:1.88.0-alpine AS builder

# Install dependencies for openssl-sys and linking
RUN apk update && apk add --no-cache \
    pkgconf \
    openssl-dev \
    musl-dev \
    build-base \
    perl \
    gcc \
    g++

WORKDIR /app

# Copy Cargo.toml and Cargo.lock first to leverage Docker cache
COPY Cargo.toml Cargo.lock ./

# Build dependencies first to cache them
RUN mkdir src && \
    echo "fn main() {println!(\"Hello, world!\");}" > src/main.rs && \
    cargo build --release && \
    rm -rf src/main.rs

# Copy source code
COPY src ./src


# Build the release binary
RUN cargo build --release

# Create a minimal runtime image
FROM alpine:latest

# Install necessary runtime dependencies (e.g., ca-certificates for HTTPS)
RUN apk add --no-cache ca-certificates libgcc
RUN apk add --no-cache socat

# Random Source
RUN apk add --no-cache rng-tools
RUN rngd -r /dev/urandom --foreground &

WORKDIR /app

COPY --from=builder /app/target/release/enclave_signer ./
COPY run.sh ./

RUN chmod +x /app/run.sh


# Command to run the application
CMD ["/app/run.sh"]