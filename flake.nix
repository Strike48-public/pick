{
  description = "Pick dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, fenix, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        # Android SDK is unfree and requires accepting its license.
        config = {
          allowUnfree = true;
          android_sdk.accept_license = true;
        };
      };

      # Rust toolchain with Android cross-compile targets.
      # nixpkgs rustc is 1.91 and cannot add targets; CLAUDE.md requires 1.92+,
      # so we pull a full stable toolchain (>=1.92) from fenix and layer the
      # Android rust-std for both device (arm64) and emulator (x86_64) targets.
      fx = fenix.packages.${system};
      rustToolchain = fx.combine [
        fx.stable.rustc
        fx.stable.cargo
        fx.stable.clippy
        fx.stable.rustfmt
        fx.stable.rust-analyzer
        fx.stable.rust-src
        fx.targets.aarch64-linux-android.stable.rust-std
        fx.targets.x86_64-linux-android.stable.rust-std
      ];

      # Android SDK/NDK. Platforms 35/36 (nixpkgs has no 34); NDK r28 stable.
      ndkVersion = "28.2.13676358";
      androidComposition = pkgs.androidenv.composeAndroidPackages {
        cmdLineToolsVersion = "9.0";
        platformToolsVersion = "36.0.2";
        buildToolsVersions = [ "35.0.1" ];
        platformVersions = [ "35" "36" ];
        includeNDK = true;
        ndkVersions = [ ndkVersion ];
        # Emulator + system images are large and left out; enable them here
        # (includeEmulator = true; includeSystemImages = true;) if you need an AVD.
      };
      androidSdk = androidComposition.androidsdk;
      androidHome = "${androidSdk}/libexec/android-sdk";
      ndkHome = "${androidHome}/ndk/${ndkVersion}";
      ndkBin = "${ndkHome}/toolchains/llvm/prebuilt/linux-x86_64/bin";

      # Gradle needs two things dx / Dioxus.toml cannot express on NixOS:
      #  1) a build-tools version nixpkgs actually ships. dx/AGP default to
      #     34.0.0, which isn't packaged, and Dioxus.toml has no build-tools
      #     field — so an init script forces it on every android module.
      #  2) the patched aapt2 from the Nix SDK. The aapt2 that AGP pulls from
      #     Maven is a plain-glibc binary that won't run on NixOS.
      # These are provisioned into a repo-local GRADLE_USER_HOME (see shellHook)
      # so they apply to dx's *own* internal Gradle run and survive dx
      # regenerating the project on every build.
      gradleProps = pkgs.writeText "gradle.properties" ''
        android.aapt2FromMavenOverride=${androidHome}/build-tools/35.0.1/aapt2
        org.gradle.jvmargs=-Xmx4g -Dfile.encoding=UTF-8
      '';
      gradleInit = pkgs.writeText "pick-android.gradle" ''
        allprojects { proj ->
            proj.afterEvaluate {
                if (proj.plugins.hasPlugin("com.android.application") || proj.plugins.hasPlugin("com.android.library")) {
                    proj.android { buildToolsVersion "35.0.1" }
                }
            }
        }
      '';

      # ----- macOS / iOS dev shell (aarch64-darwin) -----
      # iOS builds run on Apple-silicon macOS. Nix supplies the Rust toolchain
      # (with the Apple iOS std targets), `dx`, and native build deps. The iOS
      # SDK, `xcrun`, clang, simulators, and code signing come from the *system*
      # Xcode — Nix cannot vendor Apple's proprietary SDK. Install full Xcode and
      # run `sudo xcode-select --switch /Applications/Xcode.app` before building.
      darwinSystem = "aarch64-darwin";
      darwinPkgs = import nixpkgs {
        system = darwinSystem;
        config.allowUnfree = true;
      };
      fxDarwin = fenix.packages.${darwinSystem};
      darwinRust = fxDarwin.combine [
        fxDarwin.stable.rustc
        fxDarwin.stable.cargo
        fxDarwin.stable.clippy
        fxDarwin.stable.rustfmt
        fxDarwin.stable.rust-analyzer
        fxDarwin.stable.rust-src
        fxDarwin.targets.aarch64-apple-ios.stable.rust-std      # physical devices
        fxDarwin.targets.aarch64-apple-ios-sim.stable.rust-std  # Apple-silicon simulator
        fxDarwin.targets.x86_64-apple-ios.stable.rust-std       # Intel simulator (completeness)
      ];
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          rustToolchain
          pkgs.dioxus-cli   # `dx` 0.7.x, matches dioxus 0.7 in Cargo.toml
          androidSdk
          pkgs.jdk17        # Gradle / Android Gradle Plugin need a JDK
        ] ++ (with pkgs; [
          bubblewrap
          just
        ]);

        # Native build deps
        nativeBuildInputs = with pkgs; [ pkg-config protobuf ];
        buildInputs = with pkgs; [ openssl libpcap gtk3 dbus webkitgtk_4_1 libsoup_3 xdotool ];

        env = {
          # rusqlite bundled needs cc (host builds)
          CC = "cc";

          # Android toolchain discovery
          ANDROID_HOME = androidHome;
          ANDROID_SDK_ROOT = androidHome;
          ANDROID_NDK_HOME = ndkHome;
          ANDROID_NDK_ROOT = ndkHome;

          # cc-rs cross-compile toolchain (minSdk 28, matches justfile).
          CC_aarch64_linux_android = "${ndkBin}/aarch64-linux-android28-clang";
          CXX_aarch64_linux_android = "${ndkBin}/aarch64-linux-android28-clang++";
          AR_aarch64_linux_android = "${ndkBin}/llvm-ar";
          CC_x86_64_linux_android = "${ndkBin}/x86_64-linux-android28-clang";
          CXX_x86_64_linux_android = "${ndkBin}/x86_64-linux-android28-clang++";
          AR_x86_64_linux_android = "${ndkBin}/llvm-ar";

          # Cargo linkers for the Android targets.
          CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "${ndkBin}/aarch64-linux-android28-clang";
          CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER = "${ndkBin}/x86_64-linux-android28-clang";
        };

        shellHook = ''
          # Provision a repo-local GRADLE_USER_HOME with the NixOS-specific
          # Gradle shims (build-tools version + patched aapt2). Kept out of
          # ~/.gradle so we never touch the user's global Gradle config.
          export GRADLE_USER_HOME="$PWD/.gradle-nix"
          mkdir -p "$GRADLE_USER_HOME/init.d"
          install -m600 ${gradleProps} "$GRADLE_USER_HOME/gradle.properties"
          install -m600 ${gradleInit} "$GRADLE_USER_HOME/init.d/pick-android.gradle"

          # Point the justfile's `dx` (defaults to ~/.dx/bin/dx) at the Nix CLI.
          export DX_PATH="$(command -v dx)"
        '';
      };

      devShells.${darwinSystem}.default = darwinPkgs.mkShell {
        packages = [
          darwinRust
          darwinPkgs.dioxus-cli   # `dx` 0.7.x, matches dioxus 0.7 in Cargo.toml
          darwinPkgs.just
        ];

        # Native build deps. The desktop GTK/WebKit stack (gtk3, webkitgtk,
        # dbus, libsoup, xdotool) is Linux-only and irrelevant to iOS, so the
        # macOS shell stays lean.
        nativeBuildInputs = with darwinPkgs; [ pkg-config protobuf ];
        buildInputs = with darwinPkgs; [ openssl libpcap ];

        shellHook = ''
          # Point the justfile's `dx` (defaults to ~/.dx/bin/dx) at the Nix CLI.
          export DX_PATH="$(command -v dx)"

          # iOS builds need Apple's real iOS SDKs (iphoneos / iphonesimulator),
          # which Nix cannot vendor. The Nix darwin stdenv ships only a macOS SDK
          # stub plus an `xcrun` shim and points DEVELOPER_DIR at them — so cc-rs,
          # compiling ObjC deps (objc2 &c.) for an iOS target, fails on
          # `xcrun --show-sdk-path --sdk iphonesimulator`.
          #
          # When a full Xcode with the iPhone platforms is installed, defer iOS
          # SDK resolution to Apple's toolchain: point DEVELOPER_DIR at the real
          # Xcode and shadow the Nix `xcrun` shim with /usr/bin/xcrun. Rust, cargo
          # and dx still come from Nix; only Apple's SDK lookups go to Xcode. The
          # whole block is guarded on a working iphonesimulator SDK, so it is a
          # no-op (shell behaves identically) until Xcode is present.
          _dev="$(/usr/bin/xcode-select -p 2>/dev/null || true)"
          if [ -n "$_dev" ] && DEVELOPER_DIR="$_dev" /usr/bin/xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1; then
            export DEVELOPER_DIR="$_dev"
            _ios_shim="$PWD/.nix-ios-shims"
            mkdir -p "$_ios_shim"
            ln -sf /usr/bin/xcrun "$_ios_shim/xcrun"
            export PATH="$_ios_shim:$PATH"
            echo "iOS: deferring SDK resolution to system Xcode ($_dev)."
          else
            echo "WARNING: full Xcode iOS SDK not found (only a macOS SDK stub)."
            echo "  iOS builds need full Xcode, not just Command Line Tools."
            echo "  Install Xcode, then: sudo xcode-select --switch /Applications/Xcode.app"
          fi
        '';
      };
    };
}
