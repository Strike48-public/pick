{
  description = "Pick dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          # Rust
          rustc
          cargo
          clippy
          rustfmt
          rust-analyzer

          # Sandbox
          bubblewrap
        ];

        # Native build deps
        nativeBuildInputs = with pkgs; [ pkg-config protobuf ];
        buildInputs = with pkgs; [ openssl libpcap gtk3 dbus webkitgtk_4_1 libsoup_3 xdotool ];

        # rusqlite bundled needs cc
        env.CC = "cc";
      };
    };
}
