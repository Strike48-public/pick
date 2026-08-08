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

    # Opt out of Android 15's forced edge-to-edge. dx regenerates styles.xml on
    # every build with a plain NoActionBar theme; on targetSdk 35 (Android 15)
    # that makes the WebView draw UNDER the status bar, so the OS clock/battery
    # overlap Pick's brand bar. env(safe-area-inset-top) resolves to 0 in this
    # WebView (see mobile.css), so CSS can't compensate — we opt out at the theme
    # level, restoring the inset window the layout assumes on iOS and Android <=14.
    # windowOptOutEdgeToEdgeEnforcement is honored on API 35 and ignored below it.
    styles="{{proj}}/app/src/main/res/values/styles.xml"
    if [ -f "$styles" ] && ! grep -q "windowOptOutEdgeToEdgeEnforcement" "$styles"; then
        cat > "$styles" <<'XML'
    <resources>

        <!-- Base application theme. -->
        <style name="AppTheme" parent="@style/Theme.AppCompat.Light.NoActionBar">
            <!-- Opt out of Android 15 forced edge-to-edge so the WebView stays
                 below the status bar (patched by justfile _inject-android-lib). -->
            <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
        </style>
    </resources>
    XML
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

    # Allow the dx WebView to reach the localhost TCP LiveView server
    # (http://127.0.0.1:3030). The Dioxus WebView renders under a custom scheme;
    # without these cross-origin settings the shell's fetch/WebSocket to
    # 127.0.0.1:3030 is blocked. dx regenerates RustWebView.kt every build, so
    # (like the android-lib injection) this must run after dx and be idempotent.
    # android.webkit.* is already imported in the generated file, so
    # WebSettings.MIXED_CONTENT_ALWAYS_ALLOW resolves without a new import.
    webview_file="{{proj}}/app/src/main/kotlin/dev/dioxus/main/RustWebView.kt"
    anchor="settings.javaScriptCanOpenWindowsAutomatically = true"
    if [ ! -f "$webview_file" ]; then
        echo "ERROR: generated RustWebView.kt not found at $webview_file" >&2
        exit 1
    fi
    if ! grep -q "MIXED_CONTENT_ALWAYS_ALLOW" "$webview_file"; then
        if ! grep -qF "$anchor" "$webview_file"; then
            echo "ERROR: RustWebView.kt anchor not found ('$anchor'); dx template changed." >&2
            exit 1
        fi
        # Insert the four settings immediately after the anchor line. Use awk
        # (no heredoc): every line of a just recipe body must be indented, and a
        # column-0 heredoc body makes just's own parser choke before bash ever
        # runs. awk keeps this to a single indented invocation.
        awk -v anchor="$anchor" '
            { print }
            index($0, anchor) {
                print "        settings.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW"
                print "        @Suppress(\"DEPRECATION\")"
                print "        settings.allowUniversalAccessFromFileURLs = true"
                print "        settings.allowContentAccess = true"
                print "        settings.allowFileAccess = true"
            }
        ' "$webview_file" > "$webview_file.tmp" && mv "$webview_file.tmp" "$webview_file"
    fi
    if ! grep -q "MIXED_CONTENT_ALWAYS_ALLOW" "$webview_file"; then
        echo "ERROR: failed to inject WebView cross-origin settings into $webview_file" >&2
        exit 1
    fi

    # Copy restty.js into the APK assets so the WebView asset path can serve it
    # (the LiveView server also serves it over HTTP, this is the belt-and-braces
    # asset copy the original Android shell shipped).
    assets_dir="{{proj}}/app/src/main/assets/assets"
    mkdir -p "$assets_dir"
    cp crates/ui/src/assets/restty.js "$assets_dir/restty.js"

    # Replace dx's stock (green-robot) launcher icon with the strike48 brand
    # icon. dx regenerates res/mipmap-* on every build, so — like the other
    # patches here — this runs after `dx build` and is idempotent. The brand set
    # (apps/mobile/icons/res, regenerate via apps/mobile/icons/gen-android-icons.sh)
    # uses dx's EXACT filenames (ic_launcher.webp / _round.webp / _foreground.webp
    # + the adaptive XML + background color), so this copy overwrites dx's art in
    # place — no duplicate-resource error, no delete step needed.
    icon_src="apps/mobile/icons/res"
    res_dir="{{proj}}/app/src/main/res"
    if [ ! -d "$icon_src" ]; then
        echo "ERROR: brand icon set not found at $icon_src (run apps/mobile/icons/gen-android-icons.sh)" >&2
        exit 1
    fi
    # Clear any launcher .png left in the generated res dir by an older build
    # (we used to emit .png; dx never cleans stale output, so a leftover
    # ic_launcher.png would collide with our ic_launcher.webp -> "Duplicate
    # resources"). Harmless when absent.
    find "$res_dir" -type f -name 'ic_launcher*.png' -delete 2>/dev/null || true
    cp -r "$icon_src"/. "$res_dir"/
    if [ ! -f "$res_dir/mipmap-xxxhdpi/ic_launcher.webp" ]; then
        echo "ERROR: failed to inject brand launcher icon into $res_dir" >&2
        exit 1
    fi

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
    # NOTE: use `grep -c` (counts, reads to EOF), NOT `grep -q`. `grep -q` exits on
    # the first match and closes the pipe, killing the upstream `strings` with
    # SIGPIPE (exit 141); under `set -o pipefail` that turns a *successful* match on
    # a large dex into a pipeline failure, so a correctly-built APK was reported as
    # missing ConnectorBridge. Counting consumes the whole stream, so no SIGPIPE.
    found=0
    for dex in $(unzip -l "{{apk}}" 2>/dev/null | awk '/classes[0-9]*\.dex/ {print $4}'); do
        if [[ "$(unzip -p "{{apk}}" "$dex" 2>/dev/null | strings | grep -c "ConnectorBridge")" -gt 0 ]]; then
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

    # Mobile is easy-mode-first: bake PICK_EASY_MODE at build time (mobile has no
    # runtime env, and apps/mobile carries a neutral `easy_mode: false` literal so
    # the env is the single source of the default). Override by exporting
    # PICK_EASY_MODE=false before the build. The in-app Settings toggle wins over
    # either at runtime.
    export PICK_EASY_MODE="${PICK_EASY_MODE:-true}"
    echo "PICK_EASY_MODE=$PICK_EASY_MODE"

    # Bake the PLG target host so a debug install can sign in without manually
    # typing a server (mobile has no runtime env; the host reaches the binary via
    # option_env!("STRIKE48_HOST") — same mechanism release CI uses). NOT
    # hardcoded to an operator-specific URL (CLAUDE.md): export STRIKE48_HOST
    # before the build to set it. Absent, the app boots to the connect form
    # (the escape hatch) instead of silently failing sign-in.
    if [ -n "${STRIKE48_HOST:-}" ]; then
        export STRIKE48_HOST
        echo "STRIKE48_HOST=$STRIKE48_HOST (baked)"
    else
        echo "STRIKE48_HOST not set — app will show the connect form (set it to bake a default)"
    fi

    # Dev-only: bake MATRIX_TLS_INSECURE so a debug build can talk to a *.test
    # server with a self-signed / private-CA cert (main.rs reads it via
    # option_env! -> client uses danger_accept_invalid_certs). Without it, HTTPS
    # to plg.strike48.test fails with "certificate verify failed" and the app
    # shows "Connection failed". NEVER set this for a release/store build — real
    # hosts (studio.strike48.com) have valid certs.
    if [ -n "${MATRIX_TLS_INSECURE:-}" ]; then
        export MATRIX_TLS_INSECURE
        echo "MATRIX_TLS_INSECURE=$MATRIX_TLS_INSECURE (baked — dev only)"
    fi

    # Drop dev debuginfo — large disk the APK doesn't need. Overridable; output
    # correctness is unchanged.
    export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"

    # Build each Rust target. Without --target, dx builds only the host arch
    # (x86_64) and gradle silently packages stale arm64 .so files left over
    # from previous successful builds — physical devices then run obsolete
    # native code.
    targets="${ANDROID_TARGETS:-aarch64-linux-android x86_64-linux-android}"
    for target in $targets; do
        echo "==> Building Rust for $target..."
        {{dx}} build --platform android --package pick --target "$target"
    done

    # Re-inject AFTER dx (which regenerates settings.gradle and build.gradle.kts).
    just _inject-android-lib target/dx/pick/debug/android/app

    # `clean` is required: gradle's incremental task cache doesn't notice when
    # `_inject-android-lib` adds the kotlin module (settings.gradle changes
    # don't invalidate downstream task fingerprints), so without clean it can
    # silently package a stale APK that omits ConnectorBridge.
    pushd target/dx/pick/debug/android/app > /dev/null
    ./gradlew clean assembleDebug
    popd > /dev/null

    just _verify-android-apk target/dx/pick/debug/android/app/app/build/outputs/apk/debug/app-debug.apk

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

    # Mobile is easy-mode-first: bake PICK_EASY_MODE at build time (see the debug
    # build-android recipe). Override with PICK_EASY_MODE=false.
    export PICK_EASY_MODE="${PICK_EASY_MODE:-true}"
    echo "PICK_EASY_MODE=$PICK_EASY_MODE"

    # Build each Rust target. See build-android comment for why this loop matters.
    targets="${ANDROID_TARGETS:-aarch64-linux-android x86_64-linux-android}"
    for target in $targets; do
        echo "==> Building Rust for $target (release)..."
        {{dx}} build --platform android --package pick --release --target "$target"
    done

    # Re-inject AFTER dx (which regenerates settings.gradle and build.gradle.kts).
    just _inject-android-lib target/dx/pick/release/android/app

    # See build-android comment for why `clean` is required.
    pushd target/dx/pick/release/android/app > /dev/null
    ./gradlew clean assembleRelease
    popd > /dev/null

    just _verify-android-apk target/dx/pick/release/android/app/app/build/outputs/apk/release/app-release-unsigned.apk

# Build, install, and launch Android app on connected device/emulator
run-android:
    #!/usr/bin/env bash
    set -euo pipefail
    just build-android
    APK="target/dx/pick/debug/android/app/app/build/outputs/apk/debug/app-debug.apk"
    adb install -r "$APK"
    adb shell am force-stop com.strike48.pentest_connector
    adb shell am start -n com.strike48.pentest_connector/dev.dioxus.main.MainActivity

# Bundle mobile app for Android distribution as an Android App Bundle (.aab).
#
# NOTE: we deliberately do NOT use `dx bundle` here. `dx bundle` regenerates the
# Gradle project AND runs Gradle in a single step, leaving no window to inject
# the `android-lib` module (ConnectorBridge etc.) — the resulting bundle would
# build but crash at runtime with ClassNotFoundException. Instead we mirror
# `build-android-release`: `dx build` per target, then `_inject-android-lib`,
# then drive Gradle's `bundleRelease` task ourselves.
#
# The .aab is UNSIGNED (release signing needs the Play upload key we don't have
# yet). It is the distribution deliverable for issue #279; install-testing uses
# `bundle-android-universal-apk` (below), which converts it to an installable
# APK via bundletool + a throwaway debug key.
#
# By default builds both arm64 and x86_64. Override with:
#   ANDROID_TARGETS="aarch64-linux-android" just bundle-android
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

    # Mobile is easy-mode-first: bake PICK_EASY_MODE at build time (see the debug
    # build-android recipe). Override with PICK_EASY_MODE=false.
    export PICK_EASY_MODE="${PICK_EASY_MODE:-true}"
    echo "PICK_EASY_MODE=$PICK_EASY_MODE"

    # Build each Rust target. See build-android comment for why this loop matters.
    targets="${ANDROID_TARGETS:-aarch64-linux-android x86_64-linux-android}"
    for target in $targets; do
        echo "==> Building Rust for $target (release, aab)..."
        {{dx}} build --platform android --package pick --release --target "$target"
    done

    # Re-inject AFTER dx (which regenerates settings.gradle and build.gradle.kts).
    just _inject-android-lib target/dx/pick/release/android/app

    # `clean` is required for the same reason as build-android: settings.gradle
    # changes don't invalidate Gradle's task fingerprints, so a stale bundle
    # missing android-lib could otherwise be produced.
    pushd target/dx/pick/release/android/app > /dev/null
    ./gradlew clean bundleRelease
    popd > /dev/null

    AAB=target/dx/pick/release/android/app/app/build/outputs/bundle/release/app-release.aab
    if [ ! -f "$AAB" ]; then
        echo "ERROR: expected AAB not found at $AAB" >&2
        exit 1
    fi
    echo "AAB built: $AAB ($(wc -c < "$AAB") bytes)"

# Convert the release AAB into an installable universal APK for testing.
#
# An .aab cannot be installed with `adb install`. bundletool expands it into an
# APK set; `--mode=universal` yields a single APK covering all ABIs. bundletool
# requires the APK set to be signed, so we generate a THROWAWAY debug keystore
# (never for distribution — purely to make the artifact installable). Run
# `just bundle-android` first (or CI runs both in sequence).
bundle-android-universal-apk:
    #!/usr/bin/env bash
    set -euo pipefail

    AAB=target/dx/pick/release/android/app/app/build/outputs/bundle/release/app-release.aab
    if [ ! -f "$AAB" ]; then
        echo "ERROR: $AAB not found — run 'just bundle-android' first." >&2
        exit 1
    fi

    OUT=target/dx/pick/release/android
    KEYSTORE="$OUT/debug-universal.keystore"
    APKS="$OUT/app-release-universal.apks"
    APK="$OUT/pick-android-universal.apk"

    # Throwaway debug keystore (regenerated each run; NOT for distribution).
    rm -f "$KEYSTORE"
    keytool -genkeypair -v \
        -keystore "$KEYSTORE" \
        -storepass android -keypass android \
        -alias androiddebugkey \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Pick Debug, OU=CI, O=Strike48, L=NA, S=NA, C=US"

    rm -f "$APKS"
    bundletool build-apks \
        --bundle="$AAB" \
        --output="$APKS" \
        --mode=universal \
        --ks="$KEYSTORE" \
        --ks-pass=pass:android \
        --ks-key-alias=androiddebugkey \
        --key-pass=pass:android

    # The .apks archive is a zip; the universal APK is at universal.apk inside it.
    rm -f "$APK"
    unzip -p "$APKS" universal.apk > "$APK"
    echo "Universal APK: $APK ($(wc -c < "$APK") bytes)"

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
proot_version := "5.1.107.89"
talloc_version := "2.4.3"
busybox_version := "1.38.0-1"
shmem_version := "0.7"
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

        # Download and extract busybox. The Android proot layer uses busybox
        # applets (via symlinks it creates at runtime in the app files dir) to
        # bootstrap/extract the BlackArch rootfs; without libbusybox.so the shell
        # fails with "busybox binary not found". Packaged as lib*.so so the APK
        # ships it in jniLibs like proot.
        echo "Downloading busybox {{busybox_version}}..."
        curl -sL "{{termux_repo}}/b/busybox/busybox_{{busybox_version}}_${arch}.deb" -o "$TMP/busybox_${arch}.deb"
        mkdir -p "$TMP/busybox_${arch}"
        cd "$TMP/busybox_${arch}"
        ar x "../busybox_${arch}.deb"
        tar xf data.tar.xz
        # Modern Termux busybox is split: usr/bin/busybox is a tiny (~4KB)
        # launcher stub, while the real ~870KB applet multiplexer lives at
        # usr/lib/libbusybox.so.<ver>. Ship the REAL binary as libbusybox.so
        # (the proot layer runs it directly via applet symlinks).
        bb_src=$(ls ./data/data/com.termux/files/usr/lib/libbusybox.so.* 2>/dev/null | grep -v '\.so$' | head -1)
        if [ -z "$bb_src" ]; then
            echo "ERROR: real busybox lib not found in package" >&2
            exit 1
        fi
        cp -f "$bb_src" "$dest/libbusybox.so"
        echo "  -> libbusybox.so ($(wc -c < "$dest/libbusybox.so") bytes)"

        # Download and extract libandroid-shmem. proot links against it for SysV
        # IPC (shmget/shmat), which bare Android lacks; without it proot fails at
        # load with `library "libandroid-shmem.so" not found`. It is in proot's
        # ELF NEEDED list, so it must ship in jniLibs alongside libproot.so.
        echo "Downloading libandroid-shmem {{shmem_version}}..."
        curl -sL "{{termux_repo}}/liba/libandroid-shmem/libandroid-shmem_{{shmem_version}}_${arch}.deb" -o "$TMP/shmem_${arch}.deb"
        mkdir -p "$TMP/shmem_${arch}"
        cd "$TMP/shmem_${arch}"
        ar x "../shmem_${arch}.deb"
        tar xf data.tar.xz
        cp -f "./data/data/com.termux/files/usr/lib/libandroid-shmem.so" "$dest/libandroid-shmem.so"
        echo "  -> libandroid-shmem.so ($(wc -c < "$dest/libandroid-shmem.so") bytes)"

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
    # Mobile is easy-mode-first: bake PICK_EASY_MODE at build time so iOS matches
    # Android (build-android does the same). Mobile has no runtime env, so the
    # default must be baked via option_env!; without this iOS fell back to the
    # neutral expert-mode literal in apps/mobile/src/main.rs. Override with
    # PICK_EASY_MODE=false; the in-app Settings toggle still wins at runtime.
    export PICK_EASY_MODE="${PICK_EASY_MODE:-true}"
    echo "PICK_EASY_MODE=$PICK_EASY_MODE"
    {{dx}} build --platform ios --package pick
    just _inject-ios-icon target/dx/pick/debug/ios/Pick.app

# Compile the strike48 AppIcon into an iOS .app bundle. dx does not manage iOS
# icons at all (no xcassets handling), so — like _inject-android-lib — we patch
# the generated bundle after `dx build`: actool compiles
# apps/mobile/icons/ios/AppIcon.appiconset into Assets.car + emits the
# CFBundleIcons plist keys, which we merge into the app's Info.plist. macOS-only
# (actool ships with Xcode). Idempotent: re-run after every `dx build`.
_inject-ios-icon app:
    #!/usr/bin/env bash
    set -euo pipefail
    APP="{{app}}"
    ICONSET="apps/mobile/icons/ios/AppIcon.appiconset"
    if [ ! -d "$APP" ]; then echo "ERROR: app bundle not found: $APP" >&2; exit 1; fi
    if [ ! -d "$ICONSET" ]; then echo "ERROR: appiconset not found: $ICONSET" >&2; exit 1; fi
    ACTOOL="$(xcrun --find actool)"
    # actool wants the .xcassets parent dir; wrap the appiconset in a temp catalog.
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    mkdir -p "$WORK/Assets.xcassets"
    cp -R "$ICONSET" "$WORK/Assets.xcassets/"
    # Minimal catalog Contents.json.
    printf '{\n  "info" : { "author" : "xcode", "version" : 1 }\n}\n' > "$WORK/Assets.xcassets/Contents.json"
    # Compile: emits Assets.car + AppIcon*.png into $APP and writes the icon
    # plist keys (CFBundleIcons etc.) to a partial plist we merge next.
    PARTIAL="$WORK/partial.plist"
    "$ACTOOL" "$WORK/Assets.xcassets" \
        --compile "$APP" \
        --app-icon AppIcon \
        --platform iphoneos \
        --minimum-deployment-target 14.0 \
        --output-partial-info-plist "$PARTIAL" \
        --output-format human-readable-text
    # Merge the icon keys into the app's Info.plist.
    PLIST="$APP/Info.plist"
    /usr/libexec/PlistBuddy -c "Merge $PARTIAL" "$PLIST"
    if [ ! -f "$APP/Assets.car" ]; then
        echo "ERROR: actool did not produce Assets.car in $APP" >&2
        exit 1
    fi
    echo "Injected iOS AppIcon (Assets.car) into $APP"

# Run mobile app on iOS simulator (debug, hot-reload)
run-ios:
    #!/usr/bin/env bash
    set -euo pipefail
    unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH
    {{dx}} serve --platform ios --package pick

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
