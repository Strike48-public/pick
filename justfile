# Pentest Connector - Build & Run Recipes
# Run `just --list` to see all available commands

# Path to dx CLI
dx := env_var_or_default("DX_PATH", "~/.dx/bin/dx")

# Default recipe shows help
default:
    @just --list

# ============ Desktop ============

# Build desktop app
build-desktop:
    cargo build --package pentest-desktop

# Build desktop app (release)
build-desktop-release:
    cargo build --package pentest-desktop --release

# Run desktop app
run-desktop:
    cargo run --package pentest-desktop

# Run desktop app with sudo (for WiFi hardware access)
run-desktop-sudo:
    #!/usr/bin/env bash
    trap 'sudo scripts/restore-key-ownership.sh "${SUDO_USER:-$USER}" || true' EXIT
    sudo -E cargo run --package pentest-desktop

# Run desktop app (release)
run-desktop-release:
    cargo run --package pentest-desktop --release

# Run desktop app (release) with sudo
run-desktop-release-sudo:
    #!/usr/bin/env bash
    trap 'sudo scripts/restore-key-ownership.sh "${SUDO_USER:-$USER}" || true' EXIT
    sudo -E cargo run --package pentest-desktop --release

# ============ Headless Agent ============

# Default Strike48 host for development
strike_host := env_var_or_default("STRIKE48_HOST", "wss://studio.strike48.test")
strike_tenant := env_var_or_default("STRIKE48_TENANT", "non-prod")
matrix_api := env_var_or_default("MATRIX_API_URL", "https://studio.strike48.test")
matrix_tenant := env_var_or_default("MATRIX_TENANT_ID", "*")

# Run headless agent in dev mode against studio.strike48.test
dev STRIKE48_HOST="wss://studio.strike48.test" MATRIX_API_URL="https://studio.strike48.test" MATRIX_TENANT_ID="*" INSTANCE_ID="pick-dev" MATRIX_TLS_INSECURE="true" RUST_LOG="debug,hyper_util=warn,hyper=warn" STRIKE48_ACCEPT_INVALID_CERTS="true" *ARGS="":
    #!/usr/bin/env bash
    set -euo pipefail
    export STRIKE48_HOST="{{STRIKE48_HOST}}"
    export STRIKE48_TENANT="non-prod"
    export MATRIX_API_URL="{{MATRIX_API_URL}}"
    export MATRIX_TENANT_ID="{{MATRIX_TENANT_ID}}"
    export STRIKE48_INSTANCE_ID="{{INSTANCE_ID}}"
    export MATRIX_TLS_INSECURE="{{MATRIX_TLS_INSECURE}}"
    export STRIKE48_ACCEPT_INVALID_CERTS="{{STRIKE48_ACCEPT_INVALID_CERTS}}"
    export RUST_LOG="{{RUST_LOG}}"
    echo "Starting Pick connector (dev)..."
    echo "  Host:   {{STRIKE48_HOST}}"
    echo "  Tenant: {{MATRIX_TENANT_ID}}"
    echo "  Instance: {{INSTANCE_ID}}"
    echo ""
    sudo -E HOME="$HOME" PATH="$PATH" \
        CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
        RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
        cargo run --package pentest-headless -- {{ARGS}}

# Build headless agent
build-headless:
    cargo build --package pentest-headless

# Build headless agent (release)
build-headless-release:
    cargo build --package pentest-headless --release

# Run headless agent
run-headless *ARGS:
    cargo run --package pentest-headless -- {{ARGS}}

# Run headless agent (release)
run-headless-release *ARGS:
    cargo run --package pentest-headless --release -- {{ARGS}}

# Run headless agent with sudo (for WiFi hardware access)
run-headless-sudo *ARGS:
    #!/usr/bin/env bash
    # Restore ~/.strike48 ownership on exit so a later non-sudo launch can still
    # read the SDK key (see scripts/restore-key-ownership.sh).
    trap 'sudo scripts/restore-key-ownership.sh "${SUDO_USER:-$USER}" || true' EXIT
    sudo -E cargo run --package pentest-headless -- {{ARGS}}

# Run headless agent with default env vars (sudo for raw socket access)
run-headless-dev *ARGS:
    #!/usr/bin/env bash
    # Restore ~/.strike48 ownership on exit so a later non-sudo launch can still
    # read the SDK key (see scripts/restore-key-ownership.sh).
    trap 'sudo scripts/restore-key-ownership.sh "${SUDO_USER:-$USER}" || true' EXIT
    sudo -E HOME="$HOME" PATH="$PATH" \
        CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
        RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
        STRIKE48_HOST="{{strike_host}}" \
        STRIKE48_TENANT="{{strike_tenant}}" \
        MATRIX_API_URL="{{matrix_api}}" \
        MATRIX_TENANT_ID="{{matrix_tenant}}" \
        RUST_LOG="${RUST_LOG:-debug}" \
        cargo run --package pentest-headless -- {{ARGS}} 2>&1 | tee -a ~/tmp/pentest.log

# Run headless agent with custom config (reads from .env file)
run-headless-env *ARGS:
    #!/usr/bin/env bash
    set -a  # Export all variables
    [[ -f .env ]] && source .env
    set +a
    cargo run --package pentest-headless -- {{ARGS}} 2>&1 | tee -a ~/tmp/pentest.log

# ============ StrikeKit DVWA demo (matrix#3207) ============

# Compose file + its env for the Pick + DVWA live demo. Override DVWA_ENV to
# point at a different env file (the init-dev demo:pick tasks generate .env.dvwa).
dvwa_compose := "docker-compose.dvwa.yml"
dvwa_env := env_var_or_default("DVWA_ENV", ".env.dvwa")

# Validate the compose file + assert the DVWA isolation invariant (no live daemon
# needed beyond `docker compose config`). Cheap regression tripwire: fails if a
# future edit re-exposes the deliberately-vulnerable DVWA — publishes a host port,
# flips scan-net off `internal`, or attaches dvwa to the backend network.
dvwa-check:
    #!/usr/bin/env bash
    set -euo pipefail
    # Stub env so the mandatory ${VAR:?} interpolations resolve for a pure config render.
    RENDERED=$(STRIKE48_HOST=grpc://stub:80 STRIKE48_TENANT=stub MATRIX_API_URL=https://stub \
        docker compose -f "{{dvwa_compose}}" config) \
    python3 -c '
    import os, sys, yaml
    d = yaml.safe_load(os.environ["RENDERED"])
    s, n = d["services"], d["networks"]
    # `docker compose config` renders service networks as a dict (name -> opts|None),
    # not a list — normalize to the set of network names before asserting.
    dvwa_nets = set(s["dvwa"]["networks"] or [])
    errs = []
    if "ports" in s["dvwa"]: errs.append("dvwa publishes host ports (must not)")
    if dvwa_nets != {"scan-net"}: errs.append("dvwa networks != {scan-net}: %s" % sorted(dvwa_nets))
    if n["scan-net"].get("internal") is not True: errs.append("scan-net is not internal:true")
    if "backend-net" in dvwa_nets: errs.append("dvwa attached to backend-net (must not)")
    if errs:
        print("DVWA isolation FAILED:"); [print("  -", e) for e in errs]; sys.exit(1)
    print("dvwa-check OK: config valid + DVWA isolated (no host ports, scan-net internal, off backend-net)")
    '

# Bring up the Pick + DVWA demo stack (pick scans dvwa; registers with the backend)
dvwa-up *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -f "{{dvwa_env}}" ]]; then
        echo "error: {{dvwa_env}} not found — copy .env.dvwa.example to {{dvwa_env}} and set STRIKE48_TENANT" >&2
        exit 1
    fi
    docker compose --env-file "{{dvwa_env}}" -f "{{dvwa_compose}}" up --build -d {{ARGS}}
    # `up -d` returns once containers are STARTED, not proven healthy — pick has no
    # healthcheck (it's an outbound client), so confirm it didn't immediately exit
    # rather than blindly claiming success (a crash-on-boot would otherwise be hidden).
    # `ps --status running -q pick` prints the id only while pick is actually running.
    sleep 2
    if [[ -z "$(docker compose --env-file "{{dvwa_env}}" -f "{{dvwa_compose}}" ps --status running -q pick)" ]]; then
        echo "error: pick container is not running — check 'docker compose -f {{dvwa_compose}} logs pick'" >&2
        exit 1
    fi
    # pick is running, but "running" is NOT proof it registered: the connector SDK
    # RETRIES on registration failure (bad tenant UUID, unreachable/unapproved
    # backend), so it stays `running` while never appearing in Studio. Don't assert
    # PENDING here — tell the operator how to confirm it, so a silent registration
    # failure isn't masked as success.
    echo "Pick + DVWA started (pick container running)."
    echo "Confirm registration: 'docker compose -f {{dvwa_compose}} logs pick' should show a registration/pending line,"
    echo "then approve the connector in Studio -> Gateways. If it never appears, check STRIKE48_TENANT and backend reachability."

# Tear down the Pick + DVWA demo stack (add --volumes to also drop the creds volume)
dvwa-down *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    # The compose model has mandatory ${VAR:?} interpolations; if they can't
    # resolve, `down` aborts at model-parse time and leaves DVWA (a deliberately
    # vulnerable app, restart: unless-stopped) running. `down` never USES these
    # values (it identifies containers by compose project/service, not by env), so
    # default any that are unset to a stub — teardown then always succeeds even when
    # {{dvwa_env}} is absent (deleted after up, or brought up via exported vars).
    # The `:-` only substitutes when a var is unset, so a real value already in the
    # shell env is preserved; --env-file is still passed when present. (Shell env
    # takes precedence over --env-file in compose, but for `down` neither matters.)
    env_args=()
    [[ -f "{{dvwa_env}}" ]] && env_args=(--env-file "{{dvwa_env}}")
    STRIKE48_HOST="${STRIKE48_HOST:-stub}" \
    STRIKE48_TENANT="${STRIKE48_TENANT:-stub}" \
    MATRIX_API_URL="${MATRIX_API_URL:-stub}" \
        docker compose "${env_args[@]}" -f "{{dvwa_compose}}" down --remove-orphans {{ARGS}}

# ============ StrikeHub (PLG) demo (matrix#3519) ============

# Compose file + its env for the Pick + DVWA StrikeHub (PLG) demo. Sibling of the
# dvwa-* recipes: bound to a personal tenant via an OTT carried in
# STRIKE48_REGISTRATION_TOKEN, not a fixed tenant UUID. Do NOT "simplify" that to
# STRIKE48_TOKEN: that variable means an already-minted JWT, and an OTT placed
# there skips the exchange entirely (see plg-check, which asserts both).
# Override PLG_ENV to point at a different env file (the init-dev plg:pick tasks
# generate .env.plg).
plg_compose := "docker-compose.plg.yml"
plg_env := env_var_or_default("PLG_ENV", ".env.plg")

# Validate the compose file + assert the DVWA isolation invariant (no live daemon
# needed beyond `docker compose config`). Same tripwire as dvwa-check: fails if a
# future edit re-exposes the deliberately-vulnerable DVWA — publishes a host port,
# flips scan-net off `internal`, or attaches dvwa to the backend network.
plg-check:
    #!/usr/bin/env bash
    set -euo pipefail
    # Stub env so the mandatory ${VAR:?} interpolations resolve for a pure config
    # render. Note: STRIKE48_REGISTRATION_TOKEN (the OTT) is mandatory here — the
    # PLG binding — whereas STRIKE48_TENANT is intentionally NOT set (dropped from
    # this stack).
    # Assign on its own line, NOT as a `VAR=$(...) python3` prefix: in the prefix
    # form a failing command substitution does not trip `set -e`, so a compose model
    # that no longer renders (e.g. a renamed mandatory var) would reach python as an
    # empty string and crash with a TypeError instead of reporting the real problem.
    RENDERED=$(STRIKE48_HOST=grpc://stub:80 STRIKE48_REGISTRATION_TOKEN=ott_stub \
        STRIKE48_API_URL=https://stub MATRIX_API_URL=https://stub \
        docker compose -f "{{plg_compose}}" config)
    export RENDERED
    python3 -c '
    import os, sys, yaml
    d = yaml.safe_load(os.environ["RENDERED"])
    # Guard explicitly: an empty/undefined render must be a clear failure, never an
    # attribute error on None.
    if not isinstance(d, dict):
        print("plg-check FAILED:\n  - compose config produced no usable model (check the mandatory ${VAR:?} names)")
        sys.exit(1)
    s, n = d["services"], d["networks"]
    # `docker compose config` renders service networks as a dict (name -> opts|None),
    # not a list — normalize to the set of network names before asserting.
    dvwa_nets = set(s["dvwa"]["networks"] or [])
    errs = []
    if "ports" in s["dvwa"]: errs.append("dvwa publishes host ports (must not)")
    if dvwa_nets != {"scan-net"}: errs.append("dvwa networks != {scan-net}: %s" % sorted(dvwa_nets))
    if n["scan-net"].get("internal") is not True: errs.append("scan-net is not internal:true")
    if "backend-net" in dvwa_nets: errs.append("dvwa attached to backend-net (must not)")
    # PLG-specific: STRIKE48_TENANT must NOT be baked into the pick env (the OTT is
    # the binding); a stray STRIKE48_TENANT would signal a bad clone from the dvwa file.
    #
    # These assertions check the names/values the SDK ACTUALLY reads, which is the
    # whole point: an earlier revision asserted only that STRIKE48_TOKEN was
    # *present*, and passed while the stack could not register at all (the SDK never
    # reads STRIKE48_TOKEN for the OTT). Assert the real contract, incl. values.
    pick_env = s["pick"]["environment"]
    if isinstance(pick_env, list):
        pick_env = dict(e.split("=", 1) if "=" in e else (e, "") for e in pick_env)
    pick_keys = set(pick_env)
    if "STRIKE48_TENANT" in pick_keys: errs.append("pick env sets STRIKE48_TENANT (PLG binds via OTT, must not)")
    if "STRIKE48_REGISTRATION_TOKEN" not in pick_keys:
        errs.append("pick env missing STRIKE48_REGISTRATION_TOKEN (the ONLY var the SDK gates the OTT exchange on)")
    if "STRIKE48_TOKEN" in pick_keys:
        errs.append("pick env sets STRIKE48_TOKEN (that path expects an already-minted JWT; putting the OTT there skips the exchange)")
    if "STRIKE48_API_URL" not in pick_keys:
        errs.append("pick env missing STRIKE48_API_URL (the register-with-ott origin + same-origin allowlist)")
    # StrikeHub mints OTTs with connector_type "pentest-connector" (matrix_easy
    # Devices @connector_type); CONNECTOR_NAME becomes connector_type() on the wire,
    # so any other value is rejected 401 :ott_type_mismatch.
    if pick_env.get("CONNECTOR_NAME") != "pentest-connector":
        errs.append("CONNECTOR_NAME is %r, must be 'pentest-connector' to match the minted OTT type" % pick_env.get("CONNECTOR_NAME"))
    # This stack must be its OWN compose project. Without the top-level name key,
    # compose derives the project from the containing DIRECTORY, which this file
    # SHARES with docker-compose.dvwa.yml: both become project "pick" and share
    # derived networks/volumes, so a "down --remove-orphans" in either stack reaps
    # the containers of the other one. Assert the VALUE, not merely that some name
    # exists: the derived default is itself a plausible-looking name that would
    # sail through a bare presence check.
    #
    # No apostrophes or backticks anywhere in this python block: it is delimited by
    # bash single quotes (an apostrophe closes it early) and just evaluates
    # backticks itself as command substitution. Either mistake surfaces as a bash
    # syntax error on an unrelated line, not as a plg-check failure.
    if d.get("name") != "pick-plg":
        errs.append("compose project is %r, must be pick-plg (restore the top-level name key) or this stack shares networks/volumes with the dvwa demo and down --remove-orphans cross-reaps" % d.get("name"))
    if errs:
        print("plg-check FAILED:"); [print("  -", e) for e in errs]; sys.exit(1)
    print("plg-check OK: config valid + DVWA isolated + PLG bound via OTT (STRIKE48_REGISTRATION_TOKEN, no STRIKE48_TENANT) + own compose project")
    '

# Bring up the Pick + DVWA StrikeHub (PLG) stack (pick scans dvwa; registers via OTT)
plg-up *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -f "{{plg_env}}" ]]; then
        echo "error: {{plg_env}} not found — copy .env.plg.example to {{plg_env}} and set STRIKE48_REGISTRATION_TOKEN (the StrikeHub-minted OTT)" >&2
        exit 1
    fi
    docker compose --env-file "{{plg_env}}" -f "{{plg_compose}}" up --build -d {{ARGS}}
    # `up -d` returns once containers are STARTED, not proven healthy — pick has no
    # healthcheck (it's an outbound client), so confirm it didn't immediately exit
    # rather than blindly claiming success (a crash-on-boot would otherwise be hidden).
    # `ps --status running -q pick` prints the id only while pick is actually running.
    sleep 2
    if [[ -z "$(docker compose --env-file "{{plg_env}}" -f "{{plg_compose}}" ps --status running -q pick)" ]]; then
        echo "error: pick container is not running — check 'docker compose -f {{plg_compose}} logs pick'" >&2
        exit 1
    fi
    # pick is running, but "running" is NOT proof it registered: the connector SDK
    # RETRIES on registration failure (expired/invalid OTT, unreachable backend), so
    # it stays `running` while never appearing in StrikeHub. Don't assert online here
    # — tell the operator how to confirm it, so a silent registration failure isn't
    # masked as success.
    echo "Pick + DVWA (PLG) started (pick container running)."
    echo "Registering with the OTT — Pick should appear online/approved AUTOMATICALLY in"
    echo "StrikeHub -> Devices (no manual approval; the OTT is pre-approval)."
    echo "Confirm: 'docker compose -f {{plg_compose}} logs pick' should show a register-with-ott/online line."
    echo "If it never appears, the OTT may have expired (15-min TTL) — re-mint and re-run, or check backend reachability."

# Tear down the Pick + DVWA StrikeHub (PLG) stack (add --volumes to also drop the creds volume)
plg-down *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    # The compose model has mandatory ${VAR:?} interpolations; if they can't
    # resolve, `down` aborts at model-parse time and leaves DVWA (a deliberately
    # vulnerable app, restart: unless-stopped) running. `down` never USES these
    # values (it identifies containers by compose project/service, not by env), so
    # default any that are unset to a stub — teardown then always succeeds even when
    # {{plg_env}} is absent (deleted after up, or brought up via exported vars).
    # The `:-` only substitutes when a var is unset, so a real value already in the
    # shell env is preserved; --env-file is still passed when present. (Shell env
    # takes precedence over --env-file in compose, but for `down` neither matters.)
    # NOTE: default STRIKE48_REGISTRATION_TOKEN (not STRIKE48_TENANT) — this stack's
    # mandatory interpolation is the OTT, so teardown must stub THAT to parse the
    # model. Every ${VAR:?} in the compose file needs a stub here; missing one makes
    # `down` abort and leaves DVWA running.
    env_args=()
    [[ -f "{{plg_env}}" ]] && env_args=(--env-file "{{plg_env}}")
    STRIKE48_HOST="${STRIKE48_HOST:-stub}" \
    STRIKE48_REGISTRATION_TOKEN="${STRIKE48_REGISTRATION_TOKEN:-stub}" \
    STRIKE48_API_URL="${STRIKE48_API_URL:-stub}" \
    MATRIX_API_URL="${MATRIX_API_URL:-stub}" \
        docker compose "${env_args[@]}" -f "{{plg_compose}}" down --remove-orphans {{ARGS}}
    # Reap containers holding this stack's explicit `container_name` that the
    # compose `down` above did NOT match. `container_name` lives in a GLOBAL
    # docker namespace, but `down` selects by compose PROJECT label — so a
    # container created BEFORE this file gained `name: pick-plg` carries project
    # label "pick" and is invisible to `down`, while still OWNING the name
    # "pick-plg-dvwa". The next `plg-up` then dies with "Conflict. The container
    # name is already in use", and `plg-down` cannot clear it: attach/detach
    # dead-ends until the operator deletes the container by hand. The project
    # rename is still correct (it stops cross-reaping with the dvwa demo) — it
    # just needs this migration path for stacks brought up before it landed.
    # Same recovery applies to any container left behind by a `down` that
    # aborted mid-teardown.
    #
    # Named ONE BY ONE, never by prefix or glob: a `pick-*` filter would also
    # match the demo stack's pick-demo-dvwa / pick-demo-connector and reap the
    # very stack the project rename exists to protect. `--filter name=` is a
    # regex, so anchor it — unanchored, "pick-plg-dvwa" is a substring match
    # that would also catch e.g. a pick-plg-dvwa-2.
    for stray in pick-plg-dvwa pick-plg-connector; do
        if [[ -n "$(docker ps -aq --filter "name=^${stray}\$")" ]]; then
            echo "removing stray container ${stray} (holds the name but is not owned by the pick-plg compose project)"
            docker rm -f "${stray}" >/dev/null
        fi
    done

# ============ Web (Liveview) ============

# Build web app
build-web:
    cargo build --package pentest-web

# Build web app (release)
build-web-release:
    cargo build --package pentest-web --release

# Run web app (binds to 0.0.0.0:3000)
run-web:
    cargo run --package pentest-web

# Run web app (release)
run-web-release:
    cargo run --package pentest-web --release

# ============ Mobile (Android) via Dioxus CLI ============

# Android AVD name (PentestDev = rootable google_apis, PentestDevice = Play Store)
avd := env_var_or_default("AVD", "PentestDev")

# Launch Android emulator (runs in background)
emulator:
    #!/usr/bin/env bash
    set -euo pipefail
    MESA_LOADER_DRIVER_OVERRIDE=zink "${ANDROID_HOME}/emulator/emulator" -avd {{avd}} -gpu auto -writable-system &
    echo "Emulator starting {{avd}}... (PID: $!)"
    echo "Waiting for device to boot..."
    adb wait-for-device
    # Wait for boot to complete (settings service needs to be ready)
    adb shell 'while [[ "$(getprop sys.boot_completed)" != "1" ]]; do sleep 1; done'
    # Enable hardware keyboard passthrough and disable stylus handwriting
    adb shell settings put secure show_ime_with_hard_keyboard 1
    adb shell settings put secure stylus_handwriting_enabled 0
    echo "Device online! (hw keyboard enabled, stylus handwriting disabled)"

# Launch headless Android emulator (no window)
emulator-headless:
    #!/usr/bin/env bash
    set -euo pipefail
    "${ANDROID_HOME}/emulator/emulator" -avd {{avd}} -no-window -gpu swiftshader_indirect -writable-system &
    echo "Headless emulator starting {{avd}}... (PID: $!)"
    adb wait-for-device

# Inject host /etc/hosts entries into the running emulator (remaps 127.0.0.1 -> 10.0.2.2)
# Requires google_apis image (not google_apis_playstore). Run `just emulator-setup` first.
emulator-hosts:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Restarting adb as root..."
    adb root
    sleep 2
    echo "Remounting /system as writable..."
    adb remount
    sleep 1
    TMPFILE=$(mktemp)
    adb pull /system/etc/hosts "$TMPFILE" 2>/dev/null || echo -e "127.0.0.1\tlocalhost" > "$TMPFILE"
    # Append strike48.test entries, remapped to 10.0.2.2 (host loopback from emulator)
    grep 'strike48\.test' /etc/hosts | sed 's/127\.0\.0\.1/10.0.2.2/g' >> "$TMPFILE"
    adb push "$TMPFILE" /system/etc/hosts
    rm -f "$TMPFILE"
    echo "Injected hosts:"
    adb shell cat /system/etc/hosts

# Install rootable system image and create dev emulator (one-time setup)
emulator-setup:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Installing google_apis x86_64 image (rootable, no Play Store lock)..."
    "${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager" "system-images;android-36;google_apis;x86_64"
    echo ""
    echo "Creating PentestDev AVD..."
    echo "no" | "${ANDROID_HOME}/cmdline-tools/latest/bin/avdmanager" create avd \
        -n PentestDev \
        -k "system-images;android-36;google_apis;x86_64" \
        -d pixel_6 \
        --force
    CONFIG=~/.android/avd/PentestDev.avd/config.ini
    # Enable hardware keyboard for physical keyboard passthrough
    if grep -q "hw.keyboard = no" "$CONFIG"; then
        sed -i 's/hw.keyboard = no/hw.keyboard = yes/' "$CONFIG"
    elif ! grep -q "hw.keyboard = yes" "$CONFIG"; then
        echo "hw.keyboard = yes" >> "$CONFIG"
    fi
    # Increase data partition to 16GB (default 6GB is too small for BlackArch rootfs + tools)
    sed -i 's/disk.dataPartition.size = .*/disk.dataPartition.size = 17179869184/' "$CONFIG"
    echo "Done! Use 'just emulator' to launch."
    echo "Note: Data partition = 16GB, hardware keyboard enabled."

# List available Android emulators
emulator-list:
    #!/usr/bin/env bash
    "${ANDROID_HOME}/emulator/emulator" -list-avds

# Inject android-lib AAR module into a dx-generated Gradle project.
# Symlinks the module, registers it in settings.gradle, and adds the dependency.
# Idempotent — safe to call on every build.
#
# IMPORTANT: `dx build` regenerates settings.gradle and app/build.gradle.kts
# on every run, wiping out our additions. Therefore this MUST be called AFTER
# every `dx build` and BEFORE every gradle invocation. The recipe verifies the
# additions are actually present and aborts loudly if not — silently dropping
# the kotlin module produces a runtime ClassNotFoundException for
# `com.strike48.pentest_connector.ConnectorBridge` that's painful to diagnose.
_inject-android-lib proj:
    #!/usr/bin/env bash
    set -euo pipefail
    ln -sfn "$(pwd)/android-lib" "{{proj}}/android-lib"

    settings_file="{{proj}}/settings.gradle"
    build_file="{{proj}}/app/build.gradle.kts"

    grep -q "android-lib" "$settings_file" 2>/dev/null || \
        echo "include ':android-lib'" >> "$settings_file"
    grep -q "android-lib" "$build_file" 2>/dev/null || \
        echo 'dependencies { implementation(project(":android-lib")) }' >> "$build_file"

    # Verify injection took. If `dx build` regenerated the files between
    # the grep check and the echo (race), or if the project layout changed,
    # we want to know now — not at runtime.
    if ! grep -q "android-lib" "$settings_file" 2>/dev/null; then
        echo "ERROR: failed to inject android-lib into $settings_file" >&2
        exit 1
    fi
    if ! grep -q "android-lib" "$build_file" 2>/dev/null; then
        echo "ERROR: failed to inject android-lib dependency into $build_file" >&2
        exit 1
    fi

    # Copy proot, busybox, and dependencies into jniLibs
    for arch in android-jniLibs/*/; do
        abi=$(basename "$arch")
        dest="{{proj}}/app/src/main/jniLibs/$abi"
        mkdir -p "$dest"
        # Copy lib*.so and lib*.so.* (for versioned libs like libtalloc.so.2)
        cp -n "$arch"lib*.so "$dest/" 2>/dev/null || true
        cp -n "$arch"lib*.so.* "$dest/" 2>/dev/null || true
    done

# Verify the produced APK contains the kotlin bridge class.
#
# A silently-stripped `ConnectorBridge` class causes the app to crash on first
# JNI call (FetchTokenFallback → setOAuthCallbackPort →
# java.lang.ClassNotFoundException). This check catches the regression in
# seconds instead of after a 5-minute install + manual test cycle.
_verify-android-apk apk:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -f "{{apk}}" ]]; then
        echo "ERROR: APK not found: {{apk}}" >&2
        exit 1
    fi
    # APKs split classes across classes.dex, classes2.dex, etc. — scan all of them.
    found=0
    for dex in $(unzip -l "{{apk}}" 2>/dev/null | awk '/classes[0-9]*\.dex/ {print $4}'); do
        if unzip -p "{{apk}}" "$dex" 2>/dev/null | strings | grep -q "ConnectorBridge"; then
            found=1
            break
        fi
    done
    if [[ "$found" -ne 1 ]]; then
        echo "ERROR: ConnectorBridge class not found in any classes*.dex in {{apk}}" >&2
        echo "       This usually means _inject-android-lib didn't take. The app will" >&2
        echo "       crash with ClassNotFoundException on first JNI call." >&2
        exit 1
    fi
    echo "OK: ConnectorBridge present in APK"

# Helper to set up Android NDK environment - prints the NDK bin path
_android-ndk-bin:
    #!/usr/bin/env bash
    # Find NDK - check common locations
    if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
        NDK="$ANDROID_NDK_HOME"
    elif [[ -n "${ANDROID_HOME:-}" ]]; then
        # Find the highest version NDK installed
        NDK=$(ls -d "$ANDROID_HOME"/ndk/*/ 2>/dev/null | sort -V | tail -1 | sed 's:/$::')
    fi
    if [[ -z "${NDK:-}" || ! -d "$NDK" ]]; then
        echo "ERROR: Android NDK not found. Set ANDROID_NDK_HOME or install via Android Studio." >&2
        exit 1
    fi
    echo "$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"

# Build mobile app for Android (debug)
#
# By default builds both arm64 (physical devices) and x86_64 (emulators).
# Override with: ANDROID_TARGETS="aarch64-linux-android" just build-android
build-android:
    #!/usr/bin/env bash
    set -euo pipefail
    # Avoid Nix header conflicts
    unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH

    # Find and configure NDK toolchain
    NDK_BIN=$(just _android-ndk-bin)
    export PATH="$NDK_BIN:$PATH"
    echo "Using NDK toolchain from: $NDK_BIN"

    # Override CC/CXX/AR for Android targets (cc-rs uses these)
    export CC_x86_64_linux_android="$NDK_BIN/x86_64-linux-android28-clang"
    export CXX_x86_64_linux_android="$NDK_BIN/x86_64-linux-android28-clang++"
    export AR_x86_64_linux_android="$NDK_BIN/llvm-ar"
    export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang"
    export CXX_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang++"
    export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"

    # Unset global CC/CXX that would override the target-specific ones
    unset CC CXX

    # Build each Rust target. Without --target, dx builds only the host arch
    # (x86_64) and gradle silently packages stale arm64 .so files left over
    # from previous successful builds — physical devices then run obsolete
    # native code.
    targets="${ANDROID_TARGETS:-aarch64-linux-android x86_64-linux-android}"
    for target in $targets; do
        echo "==> Building Rust for $target..."
        {{dx}} build --platform android --package pentest-mobile --target "$target"
    done

    # Re-inject AFTER dx (which regenerates settings.gradle and build.gradle.kts).
    just _inject-android-lib target/dx/pentest-mobile/debug/android/app

    # `clean` is required: gradle's incremental task cache doesn't notice when
    # `_inject-android-lib` adds the kotlin module (settings.gradle changes
    # don't invalidate downstream task fingerprints), so without clean it can
    # silently package a stale APK that omits ConnectorBridge.
    pushd target/dx/pentest-mobile/debug/android/app > /dev/null
    ./gradlew clean assembleDebug
    popd > /dev/null

    just _verify-android-apk target/dx/pentest-mobile/debug/android/app/app/build/outputs/apk/debug/app-debug.apk

# Build mobile app for Android (release)
#
# By default builds both arm64 (physical devices) and x86_64 (emulators).
# Override with: ANDROID_TARGETS="aarch64-linux-android" just build-android-release
build-android-release:
    #!/usr/bin/env bash
    set -euo pipefail
    # Avoid Nix header conflicts
    unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH

    # Find and configure NDK toolchain
    NDK_BIN=$(just _android-ndk-bin)
    export PATH="$NDK_BIN:$PATH"
    echo "Using NDK toolchain from: $NDK_BIN"

    # Override CC/CXX/AR for Android targets (cc-rs uses these)
    export CC_x86_64_linux_android="$NDK_BIN/x86_64-linux-android28-clang"
    export CXX_x86_64_linux_android="$NDK_BIN/x86_64-linux-android28-clang++"
    export AR_x86_64_linux_android="$NDK_BIN/llvm-ar"
    export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang"
    export CXX_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang++"
    export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"

    # Unset global CC/CXX that would override the target-specific ones
    unset CC CXX

    # Build each Rust target. See build-android comment for why this loop matters.
    targets="${ANDROID_TARGETS:-aarch64-linux-android x86_64-linux-android}"
    for target in $targets; do
        echo "==> Building Rust for $target (release)..."
        {{dx}} build --platform android --package pentest-mobile --release --target "$target"
    done

    # Re-inject AFTER dx (which regenerates settings.gradle and build.gradle.kts).
    just _inject-android-lib target/dx/pentest-mobile/release/android/app

    # See build-android comment for why `clean` is required.
    pushd target/dx/pentest-mobile/release/android/app > /dev/null
    ./gradlew clean assembleRelease
    popd > /dev/null

    just _verify-android-apk target/dx/pentest-mobile/release/android/app/app/build/outputs/apk/release/app-release-unsigned.apk

# Build, install, and launch Android app on connected device/emulator
run-android:
    #!/usr/bin/env bash
    set -euo pipefail
    just build-android
    APK="target/dx/pentest-mobile/debug/android/app/app/build/outputs/apk/debug/app-debug.apk"
    adb install -r "$APK"
    adb shell am force-stop com.strike48.pentest_connector
    adb shell am start -n com.strike48.pentest_connector/dev.dioxus.main.MainActivity

# Bundle mobile app for Android distribution
bundle-android:
    #!/usr/bin/env bash
    set -euo pipefail
    # Avoid Nix header conflicts
    unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH

    # Find and configure NDK toolchain
    NDK_BIN=$(just _android-ndk-bin)
    export PATH="$NDK_BIN:$PATH"
    echo "Using NDK toolchain from: $NDK_BIN"

    # Override CC/CXX/AR for Android targets (cc-rs uses these)
    export CC_x86_64_linux_android="$NDK_BIN/x86_64-linux-android28-clang"
    export CXX_x86_64_linux_android="$NDK_BIN/x86_64-linux-android28-clang++"
    export AR_x86_64_linux_android="$NDK_BIN/llvm-ar"
    export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang"
    export CXX_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang++"
    export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"

    # Unset global CC/CXX that would override the target-specific ones
    unset CC CXX

    {{dx}} bundle --platform android --package pentest-mobile

# ============ Proot (Termux-patched) ============

# Build syscall_compat.so shim for proot — Android's seccomp blocks dup2/access/pipe
# but allows their newer equivalents (dup3/faccessat/pipe2). This LD_PRELOAD library
# overrides glibc to use the allowed syscalls.
build-syscall-compat:
    #!/usr/bin/env bash
    set -euo pipefail
    # Avoid Nix header conflicts
    unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH
    echo "Building syscall_compat.so for proot..."
    for arch_gcc in "x86_64:/usr/bin/gcc" "aarch64:aarch64-linux-gnu-gcc"; do
        arch="${arch_gcc%%:*}"
        gcc="${arch_gcc##*:}"
        if [ "$arch" = "aarch64" ]; then abi="arm64-v8a"; else abi="x86_64"; fi
        dest="android-jniLibs/$abi"
        mkdir -p "$dest"
        "$gcc" -shared -fPIC -nostartfiles -o "$dest/libsyscall_compat.so" syscall_compat.c
        echo "  -> $dest/libsyscall_compat.so ($(wc -c < "$dest/libsyscall_compat.so") bytes)"
    done
    echo "Done! syscall_compat shims built in android-jniLibs/"

# Termux package versions
proot_version := "5.1.107-70"
talloc_version := "2.4.3"
termux_repo := "https://packages.termux.dev/apt/termux-main/pool/main"

# Download Termux proot + dependencies for Android (x86_64 + arm64)
# Uses official Termux packages which have proper --sysvipc support for pacman
fetch-proot:
    #!/usr/bin/env bash
    set -euo pipefail
    TMP=$(mktemp -d)
    trap "rm -rf $TMP" EXIT

    for arch in x86_64 aarch64; do
        echo "=== Downloading Termux packages for $arch ==="

        # Map arch to Android ABI name
        if [ "$arch" = "aarch64" ]; then
            abi="arm64-v8a"
        else
            abi="x86_64"
        fi
        dest="{{justfile_directory()}}/android-jniLibs/$abi"
        mkdir -p "$dest"

        # Download and extract proot
        echo "Downloading proot {{proot_version}}..."
        curl -sL "{{termux_repo}}/p/proot/proot_{{proot_version}}_${arch}.deb" -o "$TMP/proot_${arch}.deb"
        mkdir -p "$TMP/proot_${arch}"
        cd "$TMP/proot_${arch}"
        ar x "../proot_${arch}.deb"
        tar xf data.tar.xz

        cp -f "./data/data/com.termux/files/usr/bin/proot"              "$dest/libproot.so"
        cp -f "./data/data/com.termux/files/usr/libexec/proot/loader"   "$dest/libproot_loader.so"
        cp -f "./data/data/com.termux/files/usr/libexec/proot/loader32" "$dest/libproot_loader32.so" 2>/dev/null || true
        echo "  -> libproot.so ($(wc -c < "$dest/libproot.so") bytes)"

        # Download and extract libtalloc (proot dependency)
        echo "Downloading libtalloc {{talloc_version}}..."
        curl -sL "{{termux_repo}}/libt/libtalloc/libtalloc_{{talloc_version}}_${arch}.deb" -o "$TMP/talloc_${arch}.deb"
        mkdir -p "$TMP/talloc_${arch}"
        cd "$TMP/talloc_${arch}"
        ar x "../talloc_${arch}.deb"
        tar xf data.tar.xz

        # Android only packages lib*.so files, so rename libtalloc.so.2 -> libtalloc.so
        cp -f "./data/data/com.termux/files/usr/lib/libtalloc.so.2" "$dest/libtalloc.so"
        echo "  -> libtalloc.so ($(wc -c < "$dest/libtalloc.so") bytes)"

        # Use patchelf to change NEEDED from libtalloc.so.2 to libtalloc.so
        # This avoids needing symlinks at runtime (Android's /data/app is read-only)
        if command -v patchelf &>/dev/null; then
            patchelf --replace-needed libtalloc.so.2 libtalloc.so "$dest/libproot.so"
            echo "  ✓ Patched libproot.so: libtalloc.so.2 -> libtalloc.so"
        elif command -v nix-shell &>/dev/null; then
            nix-shell -p patchelf --run "patchelf --replace-needed libtalloc.so.2 libtalloc.so '$dest/libproot.so'"
            echo "  ✓ Patched libproot.so: libtalloc.so.2 -> libtalloc.so (via nix)"
        else
            echo "  ⚠ WARNING: patchelf not found, libtalloc.so.2 symlink needed at runtime"
        fi

        # Verify --sysvipc support
        if strings "$dest/libproot.so" | grep -qF -- '--sysvipc'; then
            echo "  ✓ --sysvipc support confirmed"
        else
            echo "  ⚠ WARNING: --sysvipc not found in binary!"
        fi

        cd - > /dev/null
    done

    echo "Done! Termux proot + libtalloc updated in android-jniLibs/"

# ============ Mobile (iOS) via Dioxus CLI ============

# Build mobile app for iOS (debug)
build-ios:
    #!/usr/bin/env bash
    set -euo pipefail
    unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH
    {{dx}} build --platform ios --package pentest-mobile

# Run mobile app on iOS simulator (debug, hot-reload)
run-ios:
    #!/usr/bin/env bash
    set -euo pipefail
    unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH
    {{dx}} serve --platform ios --package pentest-mobile

# ============ All Targets ============

# Build all targets (debug)
build-all: build-desktop build-web build-android
    @echo "All targets built successfully!"

# Build all targets (release)
build-all-release: build-desktop-release build-web-release build-android-release
    @echo "All targets built successfully (release)!"

# ============ Development ============

# Check all code compiles
check:
    cargo check --workspace

# Run clippy lints
lint:
    cargo clippy --workspace -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Format check (CI)
fmt-check:
    cargo fmt --all -- --check

# Run tests
test:
    cargo test --workspace

# Clean build artifacts
clean:
    cargo clean

# ============ Tailwind CSS ============

# Build Tailwind CSS v4 output (requires npm install in crates/ui/)
tailwind:
    cd crates/ui && npx @tailwindcss/cli -i tailwind.css -o src/styles/tailwind-out.css --minify

# ============ Assets ============

# Bundle restty (GPU-accelerated terminal) from npm into a single IIFE for embedding
restty-bundle:
    #!/usr/bin/env bash
    set -euo pipefail
    TMP=$(mktemp -d)
    trap "rm -rf $TMP" EXIT

    echo "Downloading restty from npm..."
    cd "$TMP"
    npm pack restty@0.1.31 --pack-destination . 2>/dev/null
    tar xzf restty-*.tgz

    echo "Bundling with esbuild..."
    npx esbuild package/dist/xterm.js \
        --bundle \
        --format=iife \
        --global-name=ResttyXterm \
        --outfile=restty-bundle.js

    DEST="{{justfile_directory()}}/crates/ui/src/assets/restty.js"
    cp restty-bundle.js "$DEST"
    SIZE=$(wc -c < "$DEST")
    echo "-> $DEST ($SIZE bytes)"

# ============ Dependencies & Setup ============

# Install required tools and targets
setup:
    @echo "Installing required tools..."
    rustup target add aarch64-linux-android
    rustup target add x86_64-linux-android
    rustup target add aarch64-apple-ios
    rustup target add x86_64-apple-ios
    rustup target add aarch64-apple-ios-sim
    curl -sSLf https://dioxus.dev/install.sh | sh
    @echo ""
    @echo "Done! Make sure Android SDK/NDK is installed:"
    @echo "  ANDROID_HOME should point to Android SDK"
    @echo "  Android NDK should be installed via Android Studio"

# Run Dioxus doctor to check environment
doctor:
    {{dx}} doctor

# Show build info
info:
    @echo "Rust version:"
    @rustc --version
    @echo ""
    @echo "Cargo version:"
    @cargo --version
    @echo ""
    @echo "Dioxus CLI:"
    @{{dx}} --version || echo "dx not installed - run 'just setup'"
    @echo ""
    @echo "Installed targets:"
    @rustup target list --installed
    @echo ""
    @echo "Android SDK:"
    @echo "ANDROID_HOME=${ANDROID_HOME:-not set}"

# ============ Network Recovery ============

# Emergency WiFi recovery (fast)
fix-wifi:
    sudo ./emergency-wifi-fix.sh

# Full network recovery with diagnostics
recover-network:
    sudo ./recover-network.sh

# Show network status
network-status:
    @echo "=== Network Devices ==="
    @nmcli device status
    @echo ""
    @echo "=== WiFi Networks ==="
    @nmcli device wifi list | head -10
    @echo ""
    @echo "=== Monitor Mode Interfaces ==="
    @iw dev | grep -A5 "Interface.*mon" || echo "None"

# ============ Docker (Multi-Arch) ============

# Build multi-arch container image locally
docker-build tag="latest":
    docker buildx build \
        --platform linux/amd64 \
        --load \
        -t ghcr.io/strike48-public/pick:{{tag}} \
        -f Dockerfile.scratch .

# Build and inspect Dockerfile.scratch (dry-run to see layers)
docker-package:
    @echo "=== Dockerfile.scratch ==="
    @cat Dockerfile.scratch
    @echo ""
    @echo "=== Building locally (amd64 only, for inspection) ==="
    docker buildx build \
        --platform linux/amd64 \
        --load \
        -t pick:local-scratch \
        -f Dockerfile.scratch .
    @echo ""
    @echo "=== Image details ==="
    docker images pick:local-scratch
    @echo ""
    @echo "=== Image layers ==="
    docker history pick:local-scratch
