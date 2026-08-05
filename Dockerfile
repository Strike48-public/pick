# ── Stage 1: Chef ──────────────────────────────────────────────
FROM rust:1.91-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

# ── Stage 2: Planner ──────────────────────────────────────────
FROM chef AS planner
COPY . .
# Cargo.lock is committed; cargo chef uses it for a reproducible recipe.
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
RUN cargo chef cook --release --locked --recipe-path recipe.json -p pentest-headless --features pentest-platform/desktop-pcap

COPY . .
RUN cargo build --release --locked -p pentest-headless --features pentest-platform/desktop-pcap

# ── Stage 4: Runtime ──────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        libpcap0.8 \
        libcap2-bin \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -g 999 pick && \
    useradd -r -u 999 -g pick -m -d /data/connector pick

COPY --from=builder /app/target/release/pentest-agent /usr/local/bin/pentest-agent

# Give the pentest-agent binary raw-socket FILE capabilities so the non-root
# (uid 999) process gets them EFFECTIVE on execve. Docker's `cap_add` alone only
# fills the container bounding/permitted set, and a non-root exec clears effective
# (no ambient set) — so without this, CapEff=0 for uid 999.
#
# What this actually enables: the connector's IN-PROCESS libpcap capture path
# (crates/tools/.../traffic_capture.rs, compiled in via desktop-pcap), which opens
# raw sockets inside THIS process — so the file caps apply to it directly. It does
# NOT grant raw sockets to external scan tools (nmap/masscan/rustscan): those are
# spawned as CHILD processes, and `+ep` file caps do not cross execve to a child
# without ambient caps (which the connector never raises). Those tools also aren't
# installed in this slim image (they live in Dockerfile.scratch/Kali), so this is
# purely about the in-process capture path here.
#
# k8s is unaffected: it ships Dockerfile.scratch (runs as root → caps effective
# anyway), and even under the chart's "pentest" profile (allowPrivilegeEscalation:
# false → no_new_privs) file caps are ignored by the kernel — a no-op there. This
# only takes effect under Docker/compose. NET_RAW/NET_ADMIN must still be in the
# container bounding set (compose cap_add) for these file caps to be usable.
RUN setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/pentest-agent

RUN mkdir -p /tmp && chown pick:pick /tmp
USER pick
ENV HOME=/data/connector

ENTRYPOINT ["tini", "--", "pentest-agent"]
