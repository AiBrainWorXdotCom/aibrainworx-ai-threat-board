# Stage 1: Build Production Frontend UI
FROM node:22-bookworm-slim AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Build Single-File Rust Binary (embeds /app/frontend/dist)
FROM rust:1-bookworm AS rust-builder
RUN apt-get update && apt-get install -y --no-install-recommends libdbus-1-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /app/backend
COPY backend/Cargo.toml backend/Cargo.lock* backend/build.rs ./
COPY backend/src ./src
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
RUN cargo build --release --locked

# Stage 3: Minimal Hardened Non-Root Runtime
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libdbus-1-3 && rm -rf /var/lib/apt/lists/* \
    && groupadd --system aibrainworx \
    && useradd --system --gid aibrainworx --create-home aibrainworx \
    && mkdir -p /data \
    && chown aibrainworx:aibrainworx /data

WORKDIR /app
COPY --from=rust-builder /app/backend/target/release/aibrainworx-threat-board /usr/local/bin/aibrainworx-threat-board

ENV BIND_ADDR=0.0.0.0 \
    PORT=8080 \
    DATA_DIR=/data \
    RUST_LOG=aibrainworx_threat_board=info

VOLUME ["/data"]
EXPOSE 8080
USER aibrainworx

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/aibrainworx-threat-board"]
