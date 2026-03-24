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
    sudo -E cargo run --package pentest-desktop

# Run desktop app (release)
run-desktop-release:
    cargo run --package pentest-desktop --release

# Run desktop app (release) with sudo
run-desktop-release-sudo:
    sudo -E cargo run --package pentest-desktop --release

# ============ Headless Agent ============

# Default Strike48 host for development
strike_host := env_var_or_default("STRIKE48_HOST", "ws://localhost:3030")
strike_tenant := env_var_or_default("STRIKE48_TENANT", "non-prod")
matrix_api := env_var_or_default("MATRIX_API_URL", "http://localhost:3030")
matrix_tenant := env_var_or_default("MATRIX_TENANT_ID", "non-prod")

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
    sudo -E cargo run --package pentest-headless -- {{ARGS}}

# Run headless agent with default env vars and sudo
run-headless-dev *ARGS:
    #!/usr/bin/env bash
    sudo -E PATH="$PATH" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
        env \
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
    sudo -E PATH="$PATH" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
        cargo run --package pentest-headless -- {{ARGS}} 2>&1 | tee -a ~/tmp/pentest.log

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
    if adb devices 2>/dev/null | grep -q "emulator.*device"; then
        echo "Emulator already running."
        exit 0
    fi
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
    if adb devices 2>/dev/null | grep -q "emulator.*device"; then
        echo "Emulator already running."
        exit 0
    fi
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
_inject-android-lib proj:
    #!/usr/bin/env bash
    set -euo pipefail
    ln -sfn "$(pwd)/android-lib" "{{proj}}/android-lib"
    grep -q "android-lib" "{{proj}}/settings.gradle" 2>/dev/null || \
        echo "include ':android-lib'" >> "{{proj}}/settings.gradle"
    grep -q "android-lib" "{{proj}}/app/build.gradle.kts" 2>/dev/null || \
        echo 'dependencies { implementation(project(":android-lib")) }' >> "{{proj}}/app/build.gradle.kts"
    # Copy proot, busybox, and dependencies into jniLibs
    for arch in android-jniLibs/*/; do
        abi=$(basename "$arch")
        dest="{{proj}}/app/src/main/jniLibs/$abi"
        mkdir -p "$dest"
        # Copy lib*.so and lib*.so.* (for versioned libs like libtalloc.so.2)
        cp -n "$arch"lib*.so "$dest/" 2>/dev/null || true
        cp -n "$arch"lib*.so.* "$dest/" 2>/dev/null || true
    done
    # Copy restty.js into WebView assets so the asset loader can serve it
    assets_dir="{{proj}}/app/src/main/assets/assets"
    mkdir -p "$assets_dir"
    cp crates/ui/src/assets/restty.js "$assets_dir/restty.js"

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

    {{dx}} build --platform android --package pentest-mobile --features dev-defaults
    just _inject-android-lib target/dx/pentest-mobile/debug/android/app
    cd target/dx/pentest-mobile/debug/android/app && ./gradlew assembleDebug

# Build mobile app for Android (release)
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

    {{dx}} build --platform android --package pentest-mobile --release --features prod-defaults
    just _inject-android-lib target/dx/pentest-mobile/release/android/app
    cd target/dx/pentest-mobile/release/android/app && ./gradlew assembleRelease

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
