# Branch Test Worksheet — `josh/catching-up` (PR #249)

**Scope:** everything this branch changed vs `main` (58k insertions, 315 files). Two parts:

1. **Part A — Automatable now (no human intervention):** a per-host script the agent can run across every reachable machine. Fill in the result cells.
2. **Part B — Full feature × architecture matrix:** the complete list of what we touched and where each item must be exercised, including the manual/on-device items the agent can't drive alone.

**Reachable hosts (verified 2026-07-31):**

| Host | Arch | OS | Access | Docker/sandbox |
|------|------|-----|--------|----------------|
| local | x86_64 | Linux (NixOS) | this shell | bwrap+proot local; Docker daemon up |
| 10.10.0.8 | **arm64** | macOS 26.5 | `ssh -i ~/.ssh/id_ed25519 engineering@` | colima Docker (QEMU-TCG, slow) |
| 10.10.0.37 | x86_64 | Windows 11 | `sshpass -p engineering ssh engineering@` (password) | WSL2, distro imported |
| 10.10.0.38 | **arm64** | Windows 11 24H2 | `sshpass -p engineering ssh engineering@` (password) | WSL1 (no nested virt) |

**NOT reachable unattended:** Android arm64 (emulator blocked on NixOS binfmt gap → NixOS agent), Android x86 (needs emulator started), Intel Mac (no hardware), arm64 Linux (no hardware).

---

## Part A — Automatable test pass (agent-runnable per host)

For each host, run the applicable block. Legend: ✅ pass / ❌ fail / ⚠️ partial / — n/a / ⏭️ skipped (no backend).

### A1. Build + unit gate (Linux local only — the authoritative gate)

```bash
nix develop --command cargo fmt --all --check
nix develop --command cargo clippy --workspace --features pentest-platform/desktop-pcap -- -D warnings
nix develop --command cargo test --workspace --features pentest-platform/desktop-pcap
```

Expected: fmt clean, clippy clean, all tests pass. This is what CI runs.

### A2. Cross-compile check (Linux local — proves the other targets compile)

```bash
# Android (both arches) — needs the android dev shell / NDK
nix develop --command cargo check -p pentest-platform --no-default-features --features android --target aarch64-linux-android
nix develop --command cargo check -p pentest-platform --no-default-features --features android --target x86_64-linux-android
# iOS crux static lib (mac only — see A6)
```

### A3. Sandbox backend probe + exec-sanity (per host, the arch-aware core)

The three ignored harness tests. On each host, run whichever backend the host provides:

```bash
# Linux local (bwrap/proot, x86_64):
nix develop --command cargo test -p pentest-platform --features desktop --test backend_smoke -- --ignored --nocapture
nix develop --command cargo test -p pentest-platform --features desktop --test sandbox_backends -- --ignored --nocapture
nix develop --command cargo test -p pentest-platform --features desktop --test sandbox_integration -- --ignored test_sandbox_whoami --nocapture
```

Key assertion: `working_backend_executes_and_reports_host_arch` → guest `uname -m` == host arch.

**Windows (.37 x64, .38 arm64)** — over sshpass, if a Pick checkout + cargo exist:
```
cargo test -p pentest-platform --features desktop --test sandbox_backends -- --ignored probe_all_reports_every_os_backend --nocapture
wsl.exe -d pentest-blackarch -- uname -m     # expect x86_64 (.37) / aarch64 (.38)
```

**macOS (.8 arm64)** — Docker path, native arm64 (prepend `export PATH=/opt/homebrew/bin:$PATH;`):
```
docker run --rm --platform linux/arm64 menci/archlinuxarm:latest uname -m   # expect aarch64, NOT emulated
```

### A4. Arch-aware provisioning + REAL TOOL EXECUTION (per arch — proves a BlackArch tool actually runs, not just that the probe/DB-sync succeeds)

This is the test that matters most: a sandbox that provisions and syncs its DB can still be useless if tools won't install or execute for the arch. Every host must **install and RUN a BlackArch/Arch tool**, not just sync pacman.

**Linux x86_64 (local) — via the existing Rust integration test** (`#[cfg(target_os="linux")]`, uses `CommandExec::execute_command`):
```bash
# whoami + pacman -Sy:
nix develop --command cargo test -p pentest-platform --features desktop --test sandbox_integration -- --ignored test_sandbox_whoami test_sandbox_pacman_sync --nocapture
# THE tool-execution test: installs nmap via pacman, then runs `nmap --version`, asserts exit 0:
nix develop --command cargo test -p pentest-platform --features desktop --test sandbox_integration -- --ignored test_sandbox_install_nmap --nocapture
# (optional, heavier) raw-socket + PTY comprehensive nmap run:
nix develop --command cargo test -p pentest-platform --features desktop --test sandbox_integration -- --ignored test_sandbox_nmap_raw_sockets_comprehensive --nocapture
```
Expected: `nmap --version` exit 0 and reports a version string.

**The Rust nmap test is Linux-only.** Mac (Docker) and Windows (WSL) have no equivalent Rust test, so drive the tool run **directly** in the provisioned guest — install AND execute, both asserted:

**macOS arm64 (.8) — Docker, native arm64** (`export PATH=/opt/homebrew/bin:$PATH;`):
```bash
docker run --rm --platform linux/arm64 menci/archlinuxarm:latest bash -euxc '
  echo "Server = http://mirror.archlinuxarm.org/\$arch/\$repo" > /etc/pacman.d/mirrorlist
  pacman-key --init && pacman-key --populate archlinuxarm
  pacman -Syu --noconfirm --overwrite "*"
  printf "\n[blackarch]\nServer = https://blackarch.org/blackarch/\$repo/os/\$arch\nSigLevel = Never\n" >> /etc/pacman.conf
  pacman -Sy --noconfirm
  pacman -S --noconfirm nmap
  uname -m                 # expect aarch64
  nmap --version           # expect exit 0 + version -> the tool RAN on arm64
  nmap -sT -p 80 127.0.0.1 # a real (non-raw) scan actually executes
'
```

**Windows arm64 (.38) — WSL1, aarch64 guest:** in the provisioned `pentest-blackarch` distro (or a fresh ALARM import), same sequence: `pacman -S --noconfirm nmap` then `wsl.exe -d pentest-blackarch -- nmap --version` (expect exit 0). This is the strongest proof the aarch64 rootfs is functional — a tool installed from the arm64 BlackArch/ALARM repos and executed under WSL1 on real arm64 hardware.

**Windows x86_64 (.37) — WSL2:** `wsl.exe -d pentest-blackarch -- nmap --version` (if provisioned), or install-then-run as above. Confirms x86_64 tool execution unchanged.

**x86_64 baseline note:** the Linux-local `test_sandbox_install_nmap` already covers x86_64 tool execution via bwrap/proot; .37 covers it via WSL2.

**Caveat to log if hit:** BlackArch's arm64 repo has fewer packages than x86_64. `nmap` is in `extra`/core and must be present on both; if an *arm64-specific* tool is missing that's a known coverage limit, not a sandbox failure — record which tool.

### A5. WSL DNS fallback (S1) — Windows only

Verify the resolve-test-then-fallback: the setup script must only override DNS when the mirror host is unresolvable.
```
# On .37/.38, inspect the generated setup script / re-run distro setup and confirm:
#  - if the WSL-provided DNS resolves geo.mirror.pkgbuild.com (x64) / mirror.archlinuxarm.org (arm64),
#    resolv.conf is LEFT ALONE (no generateResolvConf=false);
#  - if it does NOT resolve, the 8.8.8.8/1.1.1.1 fallback kicks in.
```

### A6. macOS-specific builds (.8) — if repo + toolchain present

```
# iOS crux static lib cross-compile (mirrors CI ios-crux job):
nix develop --command just build-ios-crux
```

### Part A result grid

| Test | Linux x64 (local) | macOS arm64 (.8) | Win x64 (.37) | Win arm64 (.38) |
|------|:---:|:---:|:---:|:---:|
| A1 fmt/clippy/test gate | | — | — | — |
| A2 android cross-check | | — | — | — |
| A3 probe | | | | |
| A3 exec-sanity (uname==arch) | | | | |
| A4 provisioning recipe (keyring+mirror+blackarch DB sync) | | | | |
| **A4 install + RUN nmap (`nmap --version` exit 0)** | | | | |
| A4 real scan executes (`nmap -sT`) | | | | |
| A5 WSL DNS fallback | — | — | | |
| A6 iOS crux build | — | | — | — |

---

## Part B — Full feature × architecture matrix (everything touched)

Grouped by subsystem. **Platforms:** L64=Linux x86_64, LA=Linux arm64, MacA=macOS arm64, MacI=macOS Intel, WX=Win x64, WA=Win arm64, AA=Android arm64, AX=Android x86, iOS, Web. `A` = covered by a Part-A automatable test; `M` = manual/on-device; `—` = n/a; `HW?` = no hardware available.

### B1. Arch-aware sandbox (the headline work)
| Item | L64 | LA | MacA | MacI | WX | WA | AA | AX |
|------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Shared arch helper selects right rootfs/image/mirror/keyring | A | HW? | A | HW? | A | A | — | — |
| WSL aarch64 rootfs imports + execs (`uname -m`==aarch64) | — | — | — | — | — | A(.38) | — | — |
| WSL x86_64 unchanged | — | — | — | — | A(.37) | — | — | — |
| Linux bwrap/proot aarch64 rootfs | — | HW? | — | — | — | — | — | — |
| Linux bwrap/proot x86_64 unchanged | A | — | — | — | — | — | — | — |
| Docker arm64 native (menci/archlinuxarm) | — | — | A | — | — | — | — | — |
| Docker amd64 (Intel Mac / Docker-on-Linux) | A* | — | — | HW? | — | — | — | — |
| Android proot arch-aware exec-sanity | — | — | — | — | — | — | M | M |
| exec-sanity guest-arch==host-arch (Exec-format regression guard) | A | HW? | A | — | A | A(.38) | M | M |

\* Docker amd64 provisioning validated on Linux local via `docker run --platform linux/amd64`.

### B2. WSL onboarding + installer (Windows)
| Item | WX | WA |
|------|:--:|:--:|
| Probe reports WSL Working when distro imported (no cold-start stall) | A | A |
| WSL DNS resolve-test fallback (S1) | A | A |
| Guided WSL install banner shows when WSL absent | M | M |
| Guided installer: UAC elevation → feature-enable + kernel update | M | M |
| **S4: poll ElevationLaunched → surface RebootRequired/Failed** (no silent "installing…") | M | M |
| Banner dismissal persists across relaunch | M | M |
| pacman `--overwrite` clears gcc-libs/libstdc++ conflict | A | A |

### B3. Chat subscription — Phoenix v2 migration + StrikeHub WS URL
| Item | Standalone | Embedded (StrikeHub) |
|------|:--:|:--:|
| v2 array-frame join/subscribe/heartbeat acks; events stream | M(live) | M(live) |
| `resolve_ws_url` honors `__MATRIX_WS_URL__` when embedded | — | M(live) |
| Standalone derives WS URL from api_url + `vsn=2.0.0` | M(live) | — |
| Reconnect/backoff on socket drop | M(live) | M(live) |
| Streaming deltas cumulative (text/thinking); tool-call name shown | M(live) | M(live) |
| No panic on malformed/short frames | A (unit) | A (unit) |

**Requires the live StrikeHub+Matrix+plg stack — cannot be driven from CI/agent alone.** This is the highest-value manual test: the whole reason the extra StrikeHub proxy route exists as a safety net until this is confirmed.

### B4. Easy-mode / auth flow UI
| Item | Test |
|------|------|
| AuthFlow reducer transitions (incl. ChatAuthDead from SigningIn/Registering; idempotent sign-in) | A (unit) |
| **H1/H2: easy-mode connect/registration failure routes out of "Connecting…"/"Signing in…"** (status→flow bridge) | M (induce a connect failure) |
| Session-expired (expert) prompts re-sign-in; button legible | M |
| **Logout hidden when embedded in StrikeHub; shown standalone** | M (both modes) |
| Expert header shows "Pick" (not Strike48 logo) | M (visual) |
| Chat input: Enter submits, Shift+Enter newline; reads DOM value on send | M (Windows WebView2 esp.) |
| Mermaid click-to-fullscreen; chart-error XSS escaped (textContent) | M (visual) + A(js node --check) |
| Sandboxed shell-mode toggle gated on backend availability | M |
| Token persists in OS credential store across relaunch | M (per-OS keystore) |

### B5. Tools / security (merged from main + our port_scan resolution)
| Item | Test |
|------|------|
| port_scan single-host + multi-host shapes; `hosts_unreachable` aggregate | A (unit) + M(live scan) |
| Reachability: timeout→Filtered vs unreachable→Unreachable (#306) | A (unit) |
| SSRF guard: zap routes through it (#311); numeric/IPv6-encoded IP canonicalization | A (unit) |
| safety_check excludes host's own footprint (#304) | A (unit) |
| **SSDP/mDNS discovery: timeout=0 no hang; spawn_blocking; overall deadline (H3)** | A (unit) + M(live discover) |
| sanitize.rs (from main #320 — not our change) | — (upstream) |

### B6. Native mobile (crux) — the ~41% we discussed splitting out
| Item | AA | AX | iOS |
|------|:--:|:--:|:--:|
| crux-core/ffi/middleware compile per target | A (cross-check) | A | A(mac) |
| android-crux APK builds (kotlin bridge, OAuth activity) | M(CI) | M(CI) | — |
| ios-crux static lib + sim build | — | — | A(.8/CI) |
| Native OAuth callback (iOS objc2 key-window; android activity) | M(device) | M(device) | M(device) |
| Proot shell on-device | M | M | — |

### B7. Vendored patches (regression guards)
| Item | Test |
|------|------|
| dioxus-asset-resolver: non-slash asset path no panic | M (open sidebar/doc on desktop) |
| dioxus-liveview: text input no convert_form_data panic | M (type in chat, macOS/iOS) |
| Dockerfile.scratch copies vendor/ before cargo chef cook | A (CI Build amd64/arm64) |

---

## Recommended execution order

1. **A1 on Linux local** — the authoritative build/clippy/test gate (fastest signal; if this fails, stop).
2. **A3/A4 on each of the 4 reachable hosts in parallel** (agent-driven) — the arch-aware sandbox is the branch's core risk; this covers all four real arches for exec + provisioning.
3. **A5 on .37/.38** — WSL DNS fallback (S1) regression check.
4. **A6 on .8** — iOS crux build.
5. **Hand off to human/NixOS agent:** B3 (live StrikeHub chat), B2 installer UAC path, B4 UI visuals, B6 on-device mobile, Android arm64 emulator (once binfmt fixed).

## Known coverage gaps (no hardware / needs human)
- **arm64 Linux** (LA): no box — bwrap/proot aarch64 path unverified (provisioning proven-by-proxy on Mac Docker + arm64 WSL).
- **Intel Mac** (MacI): no box — Docker amd64 path unchanged from pre-branch; proven-by-proxy via Docker-on-Linux amd64.
- **Android arm64 emulator:** blocked on NixOS binfmt (`boot.binfmt.emulatedSystems`) — NixOS agent handoff pending.
- **Live chat (B3):** needs the running StrikeHub+Matrix+plg stack; agent cannot drive end-to-end. **Highest-priority manual test.**
