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
    nixpkgs.url = "git+https://github.com/NixOS/nixpkgs?ref=nixos-unstable&shallow=1";
    rust-overlay = {
      url = "git+https://github.com/oxalica/rust-overlay?shallow=1";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "git+https://github.com/numtide/flake-utils?shallow=1";
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

          # `corepack enable` (the bundled-with-Node approach) writes shims
          # next to the `node` binary, which is read-only in the Nix store —
          # it fails silently there. The standalone nixpkgs `corepack`
          # package instead ships pre-built `pnpm`/`yarn` wrapper scripts
          # that read package.json's `packageManager` field at invocation
          # time, so no write-to-the-store step is needed. Prefer the
          # Node-22-matched variant when nixpkgs has it.
          corepackPkg = if pkgs ? corepack_22 then pkgs.corepack_22 else if pkgs ? corepack then pkgs.corepack else null;
          optionalCorepack = lib.optional (corepackPkg != null) corepackPkg;

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
          ] ++ optionalCircom ++ optionalCorepack;

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
              echo "Olympus dev shell ready:"
              echo "  rustc  $(rustc --version)"
              echo "  node   $(node --version)"
              # package.json pins packageManager: pnpm@11.1.2; the nixpkgs
              # `corepack` package's pnpm wrapper reads that field and
              # fetches/uses the exact pinned version on first invocation —
              # no `corepack enable` step needed (see optionalCorepack above).
              if command -v pnpm >/dev/null 2>&1; then
                echo "  pnpm   via corepack (pinned by package.json)"
              else
                echo "  pnpm   NOT AVAILABLE — no corepack/corepack_22 attribute in this nixpkgs revision; install pnpm@11.1.2 manually" >&2
              fi
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
