# nixosModules.lighthouse (0012, 0016, 0018, 0022): kekkai-lighthouse as a hardened,
# unprivileged systemd service with a Nix-generated /etc/kekkai/lighthouse.toml. It holds
# registrations in memory only and logs aggregate counters only. Opening its UDP port in the
# host firewall is the deployment's choice (Internet exposure waits for review gate 2, 0021).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.kekkai-lighthouse;
  configPath = "/etc/kekkai/lighthouse.toml";

  settings = {
    service = {
      private_key_file = cfg.privateKeyFile;
    }
    // lib.optionalAttrs (cfg.listenPort != 4800) { listen_port = cfg.listenPort; };
    peers = lib.mapAttrsToList (name: peer: {
      inherit name;
      public_key = peer.publicKey;
    }) cfg.peers;
  }
  // lib.optionalAttrs (cfg.logLevel != "info") { log.level = cfg.logLevel; }
  // lib.optionalAttrs (cfg.metrics.listen != null) { metrics.listen = cfg.metrics.listen; };
in
{
  options.services.kekkai-lighthouse = {
    enable = lib.mkEnableOption "the kekkai lighthouse";
    package = lib.mkPackageOption pkgs "kekkai-lighthouse" { };
    cliPackage = lib.mkPackageOption pkgs "kekkai" { };

    privateKeyFile = mkOption {
      type = types.str;
      example = "/run/secrets/kekkai-lighthouse-key";
      description = ''
        Path of the lighthouse's own private key (`kekkai keygen`), readable by the
        `kekkai-lighthouse` user. Never a Nix path.
      '';
    };
    listenPort = mkOption {
      type = types.port;
      default = 4800;
      description = "UDP port of the lighthouse.";
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
      description = "Nodes by name: only listed keys complete a handshake (0012).";
    };
    logLevel = mkOption {
      type = types.str;
      default = "info";
      description = "`[log] level`, a tracing filter; `RUST_LOG` overrides it.";
    };
    metrics.listen = mkOption {
      type = types.nullOr (types.strMatching "(127\\.0\\.0\\.1|\\[::1]):[0-9]+");
      default = null;
      example = "127.0.0.1:9481";
      description = "Loopback address of the `GET /metrics` listener (0019); `null`: none.";
    };
    operators = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Users added to the `kekkai-lighthouse` group, allowed to read its status.";
    };
    configFile = mkOption {
      type = types.path;
      internal = true;
      readOnly = true;
      default = (pkgs.formats.toml { }).generate "kekkai-lighthouse.toml" settings;
      description = "The generated file, installed as ${configPath}.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [
      cfg.package
      cfg.cliPackage
    ];
    environment.etc."kekkai/lighthouse.toml".source = cfg.configFile;

    # A static user, no DynamicUser: sops-nix chowns the key before any unit runs (0018).
    users.users.kekkai-lighthouse = {
      isSystemUser = true;
      group = "kekkai-lighthouse";
    };
    users.groups.kekkai-lighthouse.members = cfg.operators;

    # `kekkai status --json --socket /run/kekkai-lighthouse/control.sock` (0030).
    systemd.sockets.kekkai-lighthouse = {
      description = "kekkai lighthouse control socket";
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "/run/kekkai-lighthouse/control.sock" ];
      socketConfig = {
        SocketUser = "root";
        SocketGroup = "kekkai-lighthouse";
        SocketMode = "0660";
      };
    };

    systemd.services.kekkai-lighthouse = {
      description = "kekkai lighthouse";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "kekkai-lighthouse.socket"
      ];
      requires = [ "kekkai-lighthouse.socket" ];
      restartTriggers = [ cfg.configFile ];
      serviceConfig = {
        Type = "notify";
        ExecStart = "${lib.getExe cfg.package} --config ${configPath}";
        Restart = "on-failure";
        User = "kekkai-lighthouse";
        Group = "kekkai-lighthouse";
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
