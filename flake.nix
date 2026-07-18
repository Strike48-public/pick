{
  description = "Pick dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Pinned solely for `dioxus-cli` 0.7.9 (our main nixpkgs pin only has 0.7.6,
    # which mismatches the dioxus 0.7.9 crates and prints a version-skew warning).
    # A cached binary — avoids building dx from source. Bump this rev to move dx.
    nixpkgs-dx.url = "github:NixOS/nixpkgs/753cc8a3a87467296ddd1fa93f0cc3e81120ee46";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, nixpkgs-dx, fenix, ... }:
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

      # dioxus-cli 0.7.9 from the pinned nixpkgs-dx input (matches the dioxus
      # 0.7.9 crates; the main pin only ships 0.7.6).
      dxCli = (import nixpkgs-dx { inherit system; }).dioxus-cli;

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
        # Emulator + a rootable google_apis x86_64 system image for android-36,
        # matching what `just emulator-setup` / `just emulator` expect. These are
        # multi-GB; they only download when someone actually enters the devshell
        # needing an AVD.
        includeEmulator = true;
        includeSystemImages = true;
        systemImageTypes = [ "google_apis" ];
        abiVersions = [ "x86_64" ];
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
      dxCliDarwin = (import nixpkgs-dx { system = darwinSystem; }).dioxus-cli;
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
          dxCli             # `dx` 0.7.9, matches dioxus 0.7.9 in Cargo.lock
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

          # Test binaries dynamically link openssl (via native-tls); without the
          # nix openssl lib on the loader path they fail at runtime with
          # "libssl.so.3: cannot open shared object file". buildInputs only
          # affects the compile/link env, not the runtime loader, so export it.
          export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.openssl ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        '';
      };

      # mkShellNoCC (not mkShell): we deliberately do NOT pull Nix's darwin cc
      # stdenv. That stdenv wraps clang/ld for a *macOS* sysroot and injects
      # `-mmacos-version-min` plus its own `xcrun` shim and DEVELOPER_DIR — all of
      # which fight iOS cross-compilation (ObjC deps get `-mmacos-version-min` vs
      # `-mios-simulator-version-min` conflicts, and cc-rs can't find the iphone
      # SDK). On a Mac with real Xcode, the system Apple toolchain already
      # compiles/links both host (macOS) and iOS targets correctly, so we let it,
      # and Nix supplies only Rust (+ iOS std), dx, and build-time tools.
      devShells.${darwinSystem}.default = darwinPkgs.mkShellNoCC {
        packages = [
          darwinRust
          dxCliDarwin   # `dx` 0.7.9, matches dioxus 0.7.9 in Cargo.lock
          darwinPkgs.just
        ];

        # Build-time tools only. protoc for build.rs; pkg-config so crates that
        # need it can still discover libs; libclang so bindgen (rquickjs-sys,
        # which ships no pre-generated iOS bindings) can parse the QuickJS
        # headers. No GTK/WebKit stack (Linux desktop only) and no Nix C
        # compiler — Apple's clang/ld from Xcode does the actual work.
        nativeBuildInputs = with darwinPkgs; [ pkg-config protobuf libclang ];

        shellHook = ''
          # Point the justfile's `dx` (defaults to ~/.dx/bin/dx) at the Nix CLI.
          export DX_PATH="$(command -v dx)"

          # bindgen (rquickjs-sys) needs libclang and, when parsing C headers for
          # an iOS target, the iOS sysroot + an Apple target triple — otherwise
          # its clang can't find stdio.h or understand the `-sim` triple suffix.
          export LIBCLANG_PATH="${darwinPkgs.libclang.lib}/lib"

          # Host + iOS compiles use Apple's clang from the active Xcode; no Nix cc
          # wrapper is present, so /usr/bin is the toolchain source. Warn early if
          # a full Xcode isn't selected (Command Line Tools alone lack the iOS SDK).
          if /usr/bin/xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1; then
            # Point bindgen at the *simulator* SDK by default — matches the
            # `dx build --platform ios` simulator flow. For a device build,
            # override with the iphoneos SDK + `-target arm64-apple-ios14.0`.
            _sim_sdk="$(/usr/bin/xcrun --sdk iphonesimulator --show-sdk-path)"
            export BINDGEN_EXTRA_CLANG_ARGS="-isysroot $_sim_sdk -target arm64-apple-ios14.0-simulator"
          else
            echo "WARNING: no iphonesimulator SDK found."
            echo "  iOS builds need full Xcode, not just Command Line Tools."
            echo "  Install Xcode, then: sudo xcode-select --switch /Applications/Xcode.app"
          fi
        '';
      };
    };
}
