# Linux build/test image for Pick, mirroring the CI Linux lane.
#
# Source of truth: .github/workflows/ci.yml, `test` job. The system deps below
# are copied from that job's "Install system dependencies" step so a local run
# reproduces CI instead of a developer's macOS host.
#
# Base is ubuntu:24.04 to match `runs-on: ubuntu-latest`. Note the ARCH gap: on
# an Apple-silicon Mac this builds aarch64; CI runs x86_64. OS parity holds; for
# a genuinely arch-sensitive check, run test.sh with PLATFORM=linux/amd64.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential pkg-config git \
      libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
      libxdo-dev protobuf-compiler libpcap-dev \
      libssl-dev cmake \
    && rm -rf /var/lib/apt/lists/*
# NOTE: libssl-dev and cmake are NOT in ci.yml's install step - the GitHub
# ubuntu-latest runner image ships them preinstalled, so CI never lists them.
# A bare ubuntu:24.04 does not, and openssl-sys / several -sys crates need them.

# Rust stable via rustup, matching dtolnay/rust-toolchain@stable in CI.
# Toolchain lives in the image; the registry cache is a runtime volume mount
# (see test.sh) so dependency downloads persist across runs.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --profile minimal \
        --component rustfmt --component clippy \
    && rustc --version && cargo --version

# Present a non-root-style HOME. The container runs as root (so the cache
# volumes stay writable), but some tests assume the runner is NOT root - e.g.
# pty_shell::test_proot_cmd_without_workspace asserts the host process HOME is
# not /root. On CI (non-root runner) and a macOS dev box that holds; with the
# default root HOME=/root it false-fails. A real non-/root HOME matches both.
RUN mkdir -p /home/build
ENV HOME=/home/build
