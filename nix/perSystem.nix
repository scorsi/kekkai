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
            echo "usage: nix run .#fuzz -- <outer_header|tlv_list|inner_message|node_config|lighthouse_config|relay_config|firewall> <seconds>" >&2
            exit 2
          fi
          exec cargo fuzz run --sanitizer none "$1" -- -max_total_time="$2"
        '';
      };
      cargoArtifacts = craneLib.buildDepsOnly rustArgs;
      # Shared node settings for the module evaluations (keys: public test vectors).
      nodeSettings = {
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
          allowInbound = [
            "tcp/22"
            "udp/53"
          ];
        };
        lighthouses = [
          {
            publicKey = "ta5DN5JdcLfn//qzn1vkBX+LgBEF698PsB10l9cpxxo=";
            endpoint = "lighthouse.example.org:4800";
          }
        ];
        relays = [
          {
            publicKey = "HZekfj15ogjJcYSkT1dubjBB7Twk+3P6/n+fHFl14Ho=";
            endpoint = "relay.example.org:4801";
          }
        ];
        firewall.udpFlowsMax = 1024;
        metrics.listen = "127.0.0.1:9480";
        operators = [ "alice" ];
      };
      lighthouseSettings = {
        enable = true;
        privateKeyFile = "/run/secrets/kekkai-lighthouse-key";
        peers.a.publicKey = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
        peers.b.publicKey = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
        metrics.listen = "127.0.0.1:9481";
        operators = [ "alice" ];
      };
      relaySettings = lighthouseSettings // {
        privateKeyFile = "/run/secrets/kekkai-relay-key";
        maxBytesPerSecond = 1000000;
        metrics.listen = "127.0.0.1:9482";
      };
      # The lighthouse or relay module against stubs of the NixOS options it sets, on this
      # system, so that `modules-eval` can run `config check` on its file with this system's
      # binary.
      serviceFile =
        name: module: settings:
        let
          stub = lib.mkOption { type = lib.types.attrsOf lib.types.anything; };
        in
        (lib.evalModules {
          modules = [
            module
            {
              config._module.args.pkgs = pkgs;
              options = {
                environment.systemPackages = lib.mkOption { type = lib.types.listOf lib.types.package; };
                environment.etc = stub;
                users.users = stub;
                users.groups = stub;
                systemd.sockets = stub;
                systemd.services = stub;
              };
              config.services.${name} = settings;
            }
          ];
        }).config.services.${name}.configFile;
      lighthouseFile =
        serviceFile "kekkai-lighthouse" inputs.self.nixosModules.lighthouse
          lighthouseSettings;
      relayFile = serviceFile "kekkai-relay" inputs.self.nixosModules.relay relaySettings;
      # The darwin node module against stubs of the nix-darwin options it sets (0018: it is
      # tested by evaluation only); `modules-eval` runs `config check` on its node file.
      darwinWith =
        extra:
        let
          stub = lib.mkOption { type = lib.types.attrsOf lib.types.anything; };
        in
        (lib.evalModules {
          modules = [
            inputs.self.darwinModules.node
            {
              config._module.args.pkgs = pkgs;
              options = {
                environment.systemPackages = lib.mkOption { type = lib.types.listOf lib.types.package; };
                environment.etc = stub;
                users.knownGroups = lib.mkOption { type = lib.types.listOf lib.types.str; };
                users.groups = stub;
                launchd.daemons = stub;
                system.activationScripts = stub;
              };
              config.services.kekkai-node = nodeSettings;
            }
            extra
          ];
        }).config;
      darwinEval = darwinWith { };
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
            services.kekkai-node = nodeSettings;
          }
        ];
      };
      # Same for the lighthouse and relay modules, with the node on the same host (0005).
      lighthouseEval = inputs.nixpkgs.lib.nixosSystem {
        modules = [
          inputs.self.nixosModules.node
          inputs.self.nixosModules.lighthouse
          inputs.self.nixosModules.relay
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
            services.kekkai-node = nodeSettings;
            services.kekkai-lighthouse = lighthouseSettings;
            services.kekkai-relay = relaySettings;
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
        # ADR 0014, milestone v0.5: kekkai-relay builds without the tunnel (kekkai-io's `tun`
        # feature, which kekkai-node enables, the control check that the pattern matches).
        relay-has-no-tunnel = craneLib.mkCargoDerivation (
          rustArgs
          // {
            inherit cargoArtifacts;
            pnameSuffix = "-relay-has-no-tunnel";
            buildPhaseCargoCommand = ''
              cargo tree --offline -p kekkai-node -e features > node.txt
              cargo tree --offline -p kekkai-relay -e features > relay.txt
              grep -q 'kekkai-io feature "tun"' node.txt
              if grep -E 'kekkai-io feature "tun"|kekkai-node ' relay.txt; then
                echo "kekkai-relay depends on the tunnel" >&2
                exit 1
              fi
            '';
            installPhaseCommand = "mkdir -p $out && cp relay.txt $out/";
          }
        );
        # The CLI build runs `go vet` and `go test`, including the shared keygen vectors (0015).
        go-test = pkgs.kekkai;

        modules-eval =
          let
            daemon = darwinEval.launchd.daemons.kekkai-node.serviceConfig;
            # nix-darwin turns `command` into ProgramArguments behind `wait4path /nix/store`.
            command = darwinEval.launchd.daemons.kekkai-node.command;
            group = darwinEval.users.groups.kekkai;
          in
          assert
            command == "${lib.getExe pkgs.kekkai-node} --config /etc/kekkai/node.toml"
            && !(daemon ? ProgramArguments);
          assert daemon.KeepAlive && daemon.RunAtLoad;
          # 0026, spec §4.1: a peer change reloads, a restart-only section restarts.
          assert
            let
              fingerprint = e: e.services.kekkai-node.restartFingerprint;
              file = e: "${e.services.kekkai-node.configFile}";
              peerChange = darwinWith {
                services.kekkai-node.peers.c = {
                  publicKey = "ta5DN5JdcLfn//qzn1vkBX+LgBEF698PsB10l9cpxxo=";
                  addresses = [ "10.0.0.9/32" ];
                };
              };
              portChange = darwinWith { services.kekkai-node.listenPort = 4803; };
            in
            fingerprint peerChange == fingerprint darwinEval
            && file peerChange != file darwinEval
            && fingerprint portChange != fingerprint darwinEval;
          assert lib.hasInfix "/bin/launchctl kill SIGHUP system/org.nixos.kekkai-node"
            darwinEval.system.activationScripts.postActivation.text;
          assert lib.all
            (
              unit:
              let
                service =
                  nodeEval.config.systemd.services.${unit} or lighthouseEval.config.systemd.services.${unit};
              in
              lib.hasSuffix "/bin/kill -HUP $MAINPID" service.serviceConfig.ExecReload
              && builtins.length service.reloadTriggers == 1
              && builtins.length service.restartTriggers == 2
            )
            [
              "kekkai-node"
              "kekkai-lighthouse"
              "kekkai-relay"
            ];
          assert group.members == [ "alice" ] && darwinEval.users.knownGroups == [ "kekkai" ];
          pkgs.runCommand "modules-eval" { } ''
            ${lib.getExe pkgs.kekkai-node} config check --config ${
              darwinEval.environment.etc."kekkai/node.toml".source
            }
            grep -q 'allow_inbound = \["tcp/22", "udp/53"\]' ${darwinEval.services.kekkai-node.configFile}
            grep -q 'udp_flows_max = 1024' ${darwinEval.services.kekkai-node.configFile}
            grep -q 'listen = "127.0.0.1:9480"' ${darwinEval.services.kekkai-node.configFile}
            grep -q 'endpoint = "lighthouse.example.org:4800"' ${darwinEval.services.kekkai-node.configFile}
            grep -q 'endpoint = "relay.example.org:4801"' ${darwinEval.services.kekkai-node.configFile}
            ${lib.getExe pkgs.kekkai-lighthouse} config check --config ${lighthouseFile}
            ${lib.getExe pkgs.kekkai-relay} config check --config ${relayFile}
            grep -q 'max_bytes_per_second = 1000000' ${relayFile}
            echo ${builtins.unsafeDiscardStringContext nodeEval.config.system.build.toplevel.drvPath} \
                 ${builtins.unsafeDiscardStringContext lighthouseEval.config.system.build.toplevel.drvPath} \
                 ${lib.concatMapStrings (p: p.name) darwinEval.environment.systemPackages} > $out
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
          validateLogs = inputs.nisshi.lib.validateLogs.${system};
          validateMetrics = inputs.masu.lib.validateMetrics.${system};
        };
        firewall = import ./tests/firewall.nix {
          inherit pkgs;
          module = inputs.self.nixosModules.node;
        };
        nat-direct = import ./tests/nat-direct.nix {
          inherit pkgs;
          nodeModule = inputs.self.nixosModules.node;
          lighthouseModule = inputs.self.nixosModules.lighthouse;
          validateLogs = inputs.nisshi.lib.validateLogs.${system};
          validateMetrics = inputs.masu.lib.validateMetrics.${system};
        };
        roaming = import ./tests/roaming.nix {
          inherit pkgs;
          nodeModule = inputs.self.nixosModules.node;
          lighthouseModule = inputs.self.nixosModules.lighthouse;
        };
        nat-relayed = import ./tests/nat-relayed.nix {
          inherit pkgs;
          nodeModule = inputs.self.nixosModules.node;
          lighthouseModule = inputs.self.nixosModules.lighthouse;
          relayModule = inputs.self.nixosModules.relay;
          validateLogs = inputs.nisshi.lib.validateLogs.${system};
          validateMetrics = inputs.masu.lib.validateMetrics.${system};
        };
        reload = import ./tests/reload.nix {
          inherit pkgs;
          nodeModule = inputs.self.nixosModules.node;
          lighthouseModule = inputs.self.nixosModules.lighthouse;
          relayModule = inputs.self.nixosModules.relay;
        };
        relay-upgrade = import ./tests/relay-upgrade.nix {
          inherit pkgs;
          nodeModule = inputs.self.nixosModules.node;
          lighthouseModule = inputs.self.nixosModules.lighthouse;
          relayModule = inputs.self.nixosModules.relay;
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
