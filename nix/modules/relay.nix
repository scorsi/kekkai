# nixosModules.relay (0014, 0016, 0018, 0022, 0031): kekkai-relay as a hardened,
# unprivileged systemd service with a Nix-generated /etc/kekkai/relay.toml. It forwards
# opaque payloads between the listed nodes, holds nothing on disk and logs aggregate
# counters only. Opening its UDP port in the host firewall is the deployment's choice
# (Internet exposure waits for review gate 2, 0021).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.kekkai-relay;
  configPath = "/etc/kekkai/relay.toml";

  settings = {
    service = {
      private_key_file = cfg.privateKeyFile;
    }
    // lib.optionalAttrs (cfg.listenPort != 4801) { listen_port = cfg.listenPort; }
    // lib.optionalAttrs (cfg.maxBytesPerSecond != null) {
      max_bytes_per_second = cfg.maxBytesPerSecond;
    };
    peers = lib.mapAttrsToList (name: peer: {
      inherit name;
      public_key = peer.publicKey;
    }) cfg.peers;
  }
  // lib.optionalAttrs (cfg.logLevel != "info") { log.level = cfg.logLevel; }
  // lib.optionalAttrs (cfg.metrics.listen != null) { metrics.listen = cfg.metrics.listen; };
in
{
  options.services.kekkai-relay = {
    enable = lib.mkEnableOption "the kekkai relay";
    package = lib.mkPackageOption pkgs "kekkai-relay" { };
    cliPackage = lib.mkPackageOption pkgs "kekkai" { };

    privateKeyFile = mkOption {
      type = types.str;
      example = "/run/secrets/kekkai-relay-key";
      description = ''
        Path of the relay's own private key (`kekkai keygen`), readable by the
        `kekkai-relay` user. Never a Nix path.
      '';
    };
    listenPort = mkOption {
      type = types.port;
      default = 4801;
      description = "UDP port of the relay.";
    };
    maxBytesPerSecond = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      example = 1000000;
      description = ''
        Per-sender rate limit: most `relay_forward` payload bytes forwarded per second for
        one node, one second's worth as burst (spec §14.2); `null`: no limit (0014).
      '';
    };
    peers = mkOption {
      type = types.attrsOf (
        types.submodule {
          options.publicKey = mkOption {
            type = types.str;
            description = "The node's public key, standard base64.";
          };
        }
      );
      default = { };
      description = "Nodes by name: only listed keys complete a handshake and may be relayed to (0014).";
    };
    logLevel = mkOption {
      type = types.str;
      default = "info";
      description = "`[log] level`, a tracing filter; `RUST_LOG` overrides it.";
    };
    metrics.listen = mkOption {
      type = types.nullOr (types.strMatching "(127\\.0\\.0\\.1|\\[::1]):[0-9]+");
      default = null;
      example = "127.0.0.1:9482";
      description = "Loopback address of the `GET /metrics` listener (0019); `null`: none.";
    };
    operators = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Users added to the `kekkai-relay` group, allowed to read its status.";
    };
    configFile = mkOption {
      type = types.path;
      internal = true;
      readOnly = true;
      default = (pkgs.formats.toml { }).generate "kekkai-relay.toml" settings;
      description = "The generated file, installed as ${configPath}.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [
      cfg.package
      cfg.cliPackage
    ];
    environment.etc."kekkai/relay.toml".source = cfg.configFile;

    # A static user, no DynamicUser: sops-nix chowns the key before any unit runs (0018).
    users.users.kekkai-relay = {
      isSystemUser = true;
      group = "kekkai-relay";
    };
    users.groups.kekkai-relay.members = cfg.operators;

    # `kekkai status --json --socket /run/kekkai-relay/control.sock` (0030).
    systemd.sockets.kekkai-relay = {
      description = "kekkai relay control socket";
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "/run/kekkai-relay/control.sock" ];
      socketConfig = {
        SocketUser = "root";
        SocketGroup = "kekkai-relay";
        SocketMode = "0660";
      };
    };

    systemd.services.kekkai-relay = {
      description = "kekkai relay";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "kekkai-relay.socket"
      ];
      requires = [ "kekkai-relay.socket" ];
      restartTriggers = [ cfg.configFile ];
      serviceConfig = {
        Type = "notify";
        ExecStart = "${lib.getExe cfg.package} --config ${configPath}";
        Restart = "on-failure";
        User = "kekkai-relay";
        Group = "kekkai-relay";
        # 0018: no capability at all, no TUN, no netlink.
        CapabilityBoundingSet = [ "" ];
        AmbientCapabilities = [ "" ];
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        ProtectSystem = "strict";
        PrivateTmp = true;
        NoNewPrivileges = true;
      };
    };
  };
}
