# docker/dev-test - CI-parity Linux build/test for Pick

Run Pick's build and test suite inside a Linux container instead of on your
host, reproducing the CI Linux lane locally.

## Why

- **Endpoint security (EDR).** On some managed macOS hosts the EDR terminates
  and quarantines test binaries that spawn adversarial argv - Pick's
  command-injection *defense* fixtures (`$(id)`-style) - deleting the binary
  mid-run. Inside the VM those processes are invisible to the host agent and run
  to completion.
- **CI parity.** It matches CI's Linux OS, so a Linux-only failure surfaces
  locally instead of only in CI on a macOS developer box.

## Requirements

Docker with a Linux backend. On macOS that is Colima (`colima start`) or Docker
Desktop; on Linux, the local Docker daemon.

## Use

Anything after the script is passed straight to `cargo`:

```sh
./docker/dev-test/test.sh                                   # full CI test line
./docker/dev-test/test.sh test -p pentest-core --locked <filter>
./docker/dev-test/test.sh check --workspace --locked --features pentest-platform/desktop-pcap
```

No args runs the exact ci.yml `test` job command. First run of a given scope
compiles; reruns are cached and fast.

## What it mirrors

The CI Linux `test` lane in `.github/workflows/ci.yml`:

- Ubuntu 24.04 + `rust stable`
- deps: `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev libxdo-dev protobuf-compiler libpcap-dev`
- `DISABLE_SANDBOX=true` (else tests download proot/rootfs and hang)
- `cargo test --workspace --locked --no-fail-fast --features pentest-platform/desktop-pcap`

## Notes and caveats

- **Extra deps.** The image also installs `libssl-dev` and `cmake`, which are
  not in ci.yml's list - the GitHub `ubuntu-latest` runner ships them
  preinstalled; a bare `ubuntu:24.04` does not.
- **Memory.** A full `test` build does full codegen for the whole graph,
  including the heavy desktop UI crate (`lucide-dioxus all-icons`). On a small
  VM, high parallelism can get `rustc` OOM-killed (SIGKILL). Cap it:
  `CARGO_BUILD_JOBS=3 ./docker/dev-test/test.sh`.
- **Runs as root.** The container runs as root so the cache volumes stay
  writable; the image sets `HOME=/home/build` so a test asserting the host
  `HOME` is not `/root` matches CI rather than false-failing.
- **Caches.** `pick-ci-registry` and `pick-ci-target` are Docker named volumes
  inside the VM, so the host `target/` is never touched. Remove with
  `docker volume rm pick-ci-registry pick-ci-target`.
- **Arch.** On Apple silicon the VM is aarch64 while CI is x86_64 - OS parity,
  not arch parity. For an arch-sensitive check:
  `PLATFORM=linux/amd64 ./docker/dev-test/test.sh ...` (slow, qemu emulation).
- **Not a malware sandbox.** A container shares the host kernel; this is a dev
  build/test runner, not an isolation boundary for untrusted samples.
