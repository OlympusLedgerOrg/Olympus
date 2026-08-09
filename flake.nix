{
  description = "Olympus development environment (Tauri 2 desktop app + Rust workspace + React frontend)";

  # Scope: this flake provides a reproducible `nix develop` shell for local
  # development only. It intentionally does NOT provide a `nix build` package
  # for the Tauri app itself:
  #   - `Cargo.toml` pins Tauri to a git rev (OlympusLedgerOrg/tauri fork),
  #     which needs a vendored/FOD-hashed source tree to build hermetically.
  #   - `proofs/setup_circuits.sh` downloads a ~150MB Powers-of-Tau file over
  #     the network during the Groth16 trusted setup.
  #   - `pg-embed-local` downloads a PostgreSQL server binary at first run.
  # None of that is impossible to make hermetic, but it's a separate, larger
  # effort (crane/naersk vendoring + fixed-output derivations for the ptau
  # and postgres fetches). Until then, use this shell and the normal
  # `cargo` / `pnpm` / `proofs/setup_circuits.sh` commands documented in
  # CLAUDE.md.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          lib = pkgs.lib;

          # Reads channel/profile/components/targets straight from
          # rust-toolchain.toml so the flake can never drift from the
          # version CI and `rustup` itself resolve.
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

          # circom's availability/name has moved around across nixpkgs
          # revisions; degrade gracefully instead of failing flake eval.
          optionalCircom = if pkgs ? circom then [ pkgs.circom ] else [ ];

          # Tauri 2 / webkit2gtk-4.1 runtime + build deps (Linux only —
          # matches the apt packages installed in .github/workflows/ci.yml).
          linuxTauriInputs = with pkgs; [
            webkitgtk_4_1
            gtk3
            libayatana-appindicator
            librsvg
            glib
            cairo
            pango
            atk
            gdk-pixbuf
            at-spi2-atk
            dbus
            patchelf
            mold
          ];

          # Apple frameworks Tauri needs to link against on macOS.
          darwinTauriInputs = with pkgs.darwin.apple_sdk.frameworks; [
            AppKit
            Carbon
            CoreServices
            Foundation
            Security
            WebKit
          ];

          commonInputs = with pkgs; [
            rustToolchain
            pkg-config
            openssl
            sqlite

            nodejs_22
          ] ++ optionalCircom;

          platformInputs =
            lib.optionals pkgs.stdenv.isLinux linuxTauriInputs
            ++ lib.optionals pkgs.stdenv.isDarwin darwinTauriInputs;

          allInputs = commonInputs ++ platformInputs;
        in
        {
          devShells.default = pkgs.mkShell {
            packages = allInputs;

            # Matches CI's `RUSTFLAGS: "-C link-arg=-fuse-ld=mold"` for faster
            # local link times; mold is Linux-only so this is a no-op elsewhere.
            RUSTFLAGS = lib.optionalString pkgs.stdenv.isLinux "-C link-arg=-fuse-ld=mold";

            # `cargo build`/`cargo tauri dev` link dynamically against the
            # GTK/WebKit stack above but aren't run through `nix build`, so
            # nothing wraps their rpath — point the dynamic linker at the
            # nix store paths ourselves.
            LD_LIBRARY_PATH = lib.optionalString pkgs.stdenv.isLinux (
              lib.makeLibraryPath linuxTauriInputs
            );

            COREPACK_ENABLE_DOWNLOAD_PROMPT = "0";

            shellHook = ''
              # package.json pins packageManager: pnpm@11.1.2; corepack
              # (bundled with nodejs_22) reads that field and fetches/uses
              # the exact pinned pnpm version on first invocation.
              corepack enable >/dev/null 2>&1 || true

              echo "Olympus dev shell ready:"
              echo "  rustc  $(rustc --version)"
              echo "  node   $(node --version)"
              echo "  pnpm   via corepack (pinned by package.json)"
              if command -v circom >/dev/null 2>&1; then
                echo "  circom $(circom --version 2>&1 | head -n1)"
              else
                echo "  circom not available in this shell — see proofs/setup_circuits.sh"
              fi
              echo
              echo "See CLAUDE.md 'Commands' for cargo/pnpm/proofs workflows."
            '';
          };

          formatter = pkgs.nixfmt-rfc-style;
        }
      );
}
