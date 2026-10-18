# Packages, devShell, checks and formatter for every system (0022).
{ inputs, ... }:
{
  perSystem =
    {
      pkgs,
      lib,
      system,
      ...
    }:
    let
      src = lib.fileset.toSource {
        root = ../.;
        fileset = lib.fileset.unions [
          ../VERSION
          ../Cargo.toml
          ../apps/cli/internal/version/version.go
        ];
      };
      # The Rust workspace sources, for crane checks.
      craneLib = inputs.crane.mkLib pkgs;
      rustArgs = {
        pname = "kekkai-workspace";
        version = lib.fileContents ../VERSION;
        strictDeps = true;
        nativeBuildInputs = [ pkgs.protobuf ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
        src = lib.fileset.toSource {
          root = ../.;
          fileset = lib.fileset.unions [
            (craneLib.fileset.commonCargoSources ../crates)
            (craneLib.fileset.commonCargoSources ../apps/node)
            (craneLib.fileset.commonCargoSources ../apps/lighthouse)
            (craneLib.fileset.commonCargoSources ../apps/relay)
            (craneLib.fileset.commonCargoSources ../fuzz)
            ../Cargo.toml
            ../Cargo.lock
            ../proto
            # kekkai-core's tests load the vectors relative to CARGO_MANIFEST_DIR (spec §19).
            ../docs/spec/vectors
            # The fuzz crate's tests replay the committed corpus (ADR 0020).
            ../fuzz/corpus
          ];
        };
      };
      # `nix run .#fuzz -- <target> <seconds>` (ADR 0020): fuzzing by hand, from the repo root,
      # with the devShell's stable toolchain, hence no sanitizer; findings land in fuzz/corpus.
      fuzz = pkgs.writeShellApplication {
        name = "kekkai-fuzz";
        runtimeInputs = with pkgs; [
          cargo
          rustc
          cargo-fuzz
        ];
        text = ''
          if [ "$#" -ne 2 ]; then
            echo "usage: nix run .#fuzz -- <outer_header|tlv_list|inner_message> <seconds>" >&2
            exit 2
          fi
          exec cargo fuzz run --sanitizer none "$1" -- -max_total_time="$2"
        '';
      };
      cargoArtifacts = craneLib.buildDepsOnly rustArgs;
      # Stub of the option NixOS and nix-darwin both provide, to evaluate the modules anywhere.
      evalModule =
        name: module:
        let
          ev = lib.evalModules {
            modules = [
              module
              {
                config._module.args.pkgs = pkgs;
                options.environment.systemPackages = lib.mkOption { type = lib.types.listOf lib.types.package; };
                config.services.${name}.enable = true;
              }
            ];
          };
        in
        lib.concatMapStrings (p: p.name) ev.config.environment.systemPackages;
      # The NixOS node module, evaluated in a full NixOS system (for aarch64-linux when this
      # system is Darwin): the drvPath forces every option and unit without building anything.
      nodeEval = inputs.nixpkgs.lib.nixosSystem {
        modules = [
          inputs.self.nixosModules.node
          {
            nixpkgs.hostPlatform = if pkgs.stdenv.hostPlatform.isLinux then system else "aarch64-linux";
            nixpkgs.overlays = [ inputs.self.overlays.default ];
            boot.loader.grub.enable = false;
            fileSystems."/" = {
              device = "none";
              fsType = "tmpfs";
            };
            system.stateVersion = "26.05";
            users.users.alice.isNormalUser = true;
            services.kekkai-node = {
              enable = true;
              privateKeyFile = "/run/secrets/kekkai-key";
              addresses = [
                "10.0.0.1/32"
                "fd00::1/128"
              ];
              peers.b = {
                publicKey = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
                addresses = [ "10.0.0.2/32" ];
                endpoints = [ "b.example.org:4802" ];
              };
              operators = [ "alice" ];
            };
          }
        ];
      };
    in
    {
      _module.args.pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [ inputs.self.overlays.default ];
      };

      packages = {
        inherit (pkgs)
          kekkai-node
          kekkai-lighthouse
          kekkai-relay
          kekkai
          ;
      };

      apps.fuzz = {
        type = "app";
        program = lib.getExe fuzz;
        meta.description = "cargo fuzz run <target> <seconds> on the parsers (ADR 0020)";
      };

      devShells.default = pkgs.mkShellNoCC {
        packages = with pkgs; [
          cargo
          rustc
          rust-analyzer
          clippy
          rustfmt
          cargo-fuzz
          go
          buf
          protobuf
          protoc-gen-go
          protoc-gen-go-grpc
          nushell
        ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
      };

      checks = {
        versions-identical =
          pkgs.runCommand "versions-identical" { nativeBuildInputs = [ pkgs.nushell ]; }
            ''
              cd ${src}
              nu ${./checks/versions-identical.nu}
              touch $out
            '';

        buf-lint = pkgs.runCommand "buf-lint" { nativeBuildInputs = [ pkgs.buf ]; } ''
          export HOME=$TMPDIR
          cd ${../proto}
          buf lint
          touch $out
        '';

        # The committed Go client must match what `buf generate` produces.
        buf-generate =
          pkgs.runCommand "buf-generate"
            {
              nativeBuildInputs = with pkgs; [
                buf
                protoc-gen-go
                protoc-gen-go-grpc
              ];
              src = lib.fileset.toSource {
                root = ../.;
                fileset = lib.fileset.unions [
                  ../proto
                  ../apps/cli/internal/genproto
                ];
              };
            }
            ''
              export HOME=$TMPDIR
              cp -r $src work && chmod -R u+w work
              rm -r work/apps/cli/internal/genproto
              (cd work/proto && buf generate)
              diff -r $src/apps/cli/internal/genproto work/apps/cli/internal/genproto
              touch $out
            '';

        cargo-clippy = craneLib.cargoClippy (
          rustArgs
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          }
        );
        cargo-test = craneLib.cargoTest (rustArgs // { inherit cargoArtifacts; });
        # The CLI build runs `go vet` and `go test`, including the shared keygen vectors (0015).
        go-test = pkgs.kekkai;

        modules-eval = pkgs.runCommand "modules-eval" { } ''
          echo ${builtins.unsafeDiscardStringContext nodeEval.config.system.build.toplevel.drvPath} \
               ${evalModule "kekkai-lighthouse" inputs.self.nixosModules.lighthouse} \
               ${evalModule "kekkai-relay" inputs.self.nixosModules.relay} \
               ${evalModule "kekkai-node" inputs.self.darwinModules.node} > $out
        '';
      }
      // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        nixos-node-version = import ./tests/node-version.nix {
          inherit pkgs;
          module = inputs.self.nixosModules.node;
        };
        two-nodes = import ./tests/two-nodes.nix {
          inherit pkgs;
          module = inputs.self.nixosModules.node;
        };
      };

      treefmt = {
        projectRootFile = "flake.nix";
        programs = {
          rustfmt.enable = true;
          gofmt.enable = true;
          nixfmt.enable = true;
        };
        settings.excludes = [
          "apps/cli/internal/genproto/**"
          "target/**"
          "Cargo.lock"
          "LICENSE"
        ];
      };
    };
}
