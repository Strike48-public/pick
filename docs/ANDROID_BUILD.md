# Android Build Guide

This guide covers building the Pick Android app from source, deploying to devices, and troubleshooting common issues.

## Prerequisites

### 1. Android SDK & NDK

Install Android SDK and NDK via Android Studio or command-line tools:

```bash
# Check if already installed
echo $ANDROID_HOME
# Should output: /path/to/Android/Sdk

# Verify NDK installation
ls $ANDROID_HOME/ndk/
# Should show at least one NDK version (e.g., 29.0.14033849)
```

**Required components:**
- Android SDK Platform 34 (compileSdk)
- Android SDK Build-Tools
- Android NDK (tested with 29.0.14033849)
- Android SDK Platform-Tools (for adb)

### 2. Rust Android Targets

Install cross-compilation targets:

```bash
rustup target add aarch64-linux-android    # ARM64 (most devices)
rustup target add armv7-linux-androideabi  # ARMv7 (older devices)
rustup target add x86_64-linux-android     # x86_64 emulators
rustup target add i686-linux-android       # x86 emulators
```

Verify installation:

```bash
rustup target list --installed | grep android
```

### 3. Dioxus CLI

Install the Dioxus CLI for building mobile apps:

```bash
cargo install dioxus-cli --version 0.7.3
```

Set `DX_PATH` environment variable (if not using default location):

```bash
export DX_PATH="$(which dx)"
```

### 4. Java Development Kit

Gradle requires JDK 17 or later:

```bash
java --version
# Should show version 17 or higher
```

## Build Commands

### Debug Build (Development)

Build for all architectures with debug symbols:

```bash
just build-android
```

This command:
1. Sets up NDK toolchain paths
2. Runs `dx build --platform android --package pentest-mobile`
3. Injects `android-lib` Kotlin bridge module
4. Runs `./gradlew assembleDebug`

Output: `target/dx/pentest-mobile/debug/android/app/app/build/outputs/apk/debug/app-debug.apk`

### Release Build (Production)

Build optimized APK with release configuration:

```bash
just build-android-release
```

Output: `target/dx/pentest-mobile/release/android/app/app/build/outputs/apk/release/app-release-unsigned.apk`

**Note:** Release APKs must be signed before distribution. See signing documentation (TBD).

### Architecture-Specific Builds

Build for a specific target only:

```bash
# ARM64 only (most physical devices)
export DX_PATH="$(which dx)"
dx build --platform android --package pentest-mobile --target aarch64-linux-android

# x86_64 only (emulators)
dx build --platform android --package pentest-mobile --target x86_64-linux-android
```

## Deployment

### Prerequisites

1. Enable USB debugging on device:
   - Go to Settings > About Phone
   - Tap "Build Number" 7 times to enable Developer Options
   - Go to Settings > Developer Options
   - Enable "USB debugging"

2. Connect device via USB and verify:

```bash
adb devices -l
```

Expected output:
```
List of devices attached
XXXXXXXXXXXXXX    device usb:X-X.X.X product:... model:... device:...
```

If you see "unauthorized", accept the USB debugging prompt on your device.

### Install and Launch

Use the convenience command:

```bash
just run-android
```

This will:
1. Build the debug APK (if needed)
2. Install it: `adb install -r app-debug.apk`
3. Force-stop any existing instance
4. Launch the app

### Manual Installation

```bash
# Install APK
APK="target/dx/pentest-mobile/debug/android/app/app/build/outputs/apk/debug/app-debug.apk"
adb install -r "$APK"

# Launch app
adb shell am start -n com.strike48.pentest_connector/.MainActivity
```

## Debugging

### View Logs

Monitor app logs in real-time:

```bash
# All app logs
adb logcat | grep PentestConnector

# Rust panic backtraces
adb logcat | grep -E "(RUST|panic|backtrace)"

# JNI bridge logs
adb logcat | grep AndroidBridge

# Kotlin/Java logs
adb logcat | grep -E "(ConnectorBridge|ConnectorService)"
```

### Check App Behavior

```bash
# Force-stop app
adb shell am force-stop com.strike48.pentest_connector

# Clear app data
adb shell pm clear com.strike48.pentest_connector

# Check permissions
adb shell dumpsys package com.strike48.pentest_connector | grep permission

# Check if service is running
adb shell dumpsys activity services | grep ConnectorService
```

### Inspect APK Contents

```bash
# List files in APK
unzip -l app-debug.apk

# Check included JNI libraries
unzip -l app-debug.apk | grep "\.so$"

# Expected architectures:
# - lib/arm64-v8a/libdioxusmain.so   (ARM64 devices)
# - lib/armeabi-v7a/libdioxusmain.so (ARMv7 devices)
# - lib/x86_64/libdioxusmain.so      (x86_64 emulators)
# - lib/x86/libdioxusmain.so         (x86 emulators)
```

## android-lib Module

The `android-lib/` directory contains Kotlin/Java bridge code for Android platform features:

- **OAuthCallbackActivity.kt**: Handle OAuth2 redirect URIs
- **ConnectorService.kt**: Foreground service for background execution
- **ScreenCaptureService.kt**: MediaProjection for screenshot capture
- **PacketCaptureVpnService.kt**: VPN-based packet capture
- **PermissionRequester.kt**: Runtime permission flow orchestration
- **ConnectorBridge.kt**: JNI bridge between Rust and Kotlin

This module is automatically injected into the dx-generated Gradle project during build.

## Troubleshooting

### Build Issues

**Error: `dx: command not found`**

Solution: Set `DX_PATH` environment variable:
```bash
export DX_PATH="$(which dx)"
# Or add to ~/.bashrc:
echo 'export DX_PATH="$(which dx)"' >> ~/.bashrc
```

**Error: `ANDROID_HOME not set`**

Solution: Set Android SDK path:
```bash
export ANDROID_HOME="$HOME/Android/Sdk"
# Or wherever your SDK is installed
```

**Error: NDK not found**

Solution: Install NDK via Android Studio or sdkmanager:
```bash
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager "ndk;29.0.14033849"
```

**Error: Rust target not installed**

Solution: Install missing target:
```bash
rustup target add <target-triple>
# Example: rustup target add aarch64-linux-android
```

**Error: `cc-rs` compilation failures**

This usually means NDK toolchain paths aren't configured. The justfile handles this automatically. If building manually:

```bash
NDK="$ANDROID_HOME/ndk/29.0.14033849"
NDK_BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
export PATH="$NDK_BIN:$PATH"
export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"
```

**Error: Nix header conflicts**

If building in a Nix environment, unset conflicting paths:
```bash
unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH
```

### Runtime Issues

**App crashes immediately on launch**

Check logcat for panic messages:
```bash
adb logcat | grep -E "(RUST_BACKTRACE|panic)"
```

Common causes:
- Missing JNI library for device architecture
- JNI method signature mismatch
- Uninitialized Rust state

**"Library not found" errors**

Verify the correct architecture library is included:
```bash
# Check device architecture
adb shell getprop ro.product.cpu.abi
# Examples: arm64-v8a, armeabi-v7a, x86_64, x86

# Check if library exists for that architecture
unzip -l app-debug.apk | grep lib/<arch>/libdioxusmain.so
```

**Permission denied errors**

Check if permissions are declared in `AndroidManifest.xml` and requested at runtime:
```bash
# View app manifest
aapt dump badging app-debug.apk | grep permission

# Check granted permissions
adb shell dumpsys package com.strike48.pentest_connector | grep "granted=true"
```

### Emulator vs Physical Device

**Emulators:**
- Use `x86_64` or `x86` targets
- May not support all Android features (VPN, some sensors)
- Useful for quick testing and CI/CD

**Physical Devices:**
- Require `arm64-v8a` or `armeabi-v7a` targets
- Full feature support
- Better performance testing
- Required for testing root/proot modes

## Build Artifacts

After a successful build, the following structure is created:

```
target/dx/pentest-mobile/debug/android/app/
├── android-lib/          # Symlink to ../../../../../../android-lib
├── app/
│   ├── build/
│   │   ├── outputs/apk/debug/
│   │   │   └── app-debug.apk
│   │   └── intermediates/
│   │       └── merged_native_libs/
│   │           └── debug/
│   │               └── mergeDebugNativeLibs/out/lib/
│   │                   ├── arm64-v8a/libdioxusmain.so
│   │                   ├── armeabi-v7a/libdioxusmain.so
│   │                   ├── x86_64/libdioxusmain.so
│   │                   └── x86/libdioxusmain.so
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── res/
├── build.gradle
├── settings.gradle
└── gradlew
```

## Next Steps

After successful build and deployment:

1. **Functional Testing**: Test OAuth, WiFi scanning, shell execution
2. **Permission Flow**: Verify runtime permission requests
3. **Root vs Proot**: Test tool execution in both modes
4. **Performance**: Monitor memory/CPU usage
5. **Background Execution**: Test foreground service behavior

## Related Documentation

- [Android Platform Integration](../crates/platform/src/android/README.md) (TBD)
- [Root vs Proot Mode](./ANDROID_ROOT_MODES.md) (TBD)
- [APK Signing & Distribution](./ANDROID_SIGNING.md) (TBD)
