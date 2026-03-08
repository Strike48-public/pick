# ── Stage 1: Chef ──────────────────────────────────────────────
FROM rust:1.88-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

# ── Stage 2: Planner ──────────────────────────────────────────
FROM chef AS planner
COPY . .
# Generate lockfile if missing (Cargo.lock is gitignored)
RUN test -f Cargo.lock || cargo generate-lockfile
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: Builder ──────────────────────────────────────────
FROM chef AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        protobuf-compiler \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=planner /app/recipe.json recipe.json

# Cook dependencies (cached as long as recipe.json is unchanged)
RUN cargo chef cook --release --recipe-path recipe.json -p pentest-headless --features pentest-platform/desktop-pcap

COPY . .
RUN test -f Cargo.lock || cargo generate-lockfile
RUN cargo build --release -p pentest-headless --features pentest-platform/desktop-pcap

# ── Stage 4: Runtime ──────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        libpcap0.8 \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -g 999 pick && \
    useradd -r -u 999 -g pick -m -d /data/connector pick

COPY --from=builder /app/target/release/pentest-agent /usr/local/bin/pentest-agent

RUN mkdir -p /tmp && chown pick:pick /tmp
USER pick
ENV HOME=/data/connector

ENTRYPOINT ["tini", "--", "pentest-agent"]
