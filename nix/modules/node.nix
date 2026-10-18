# nixosModules.node (0016, 0018, 0022): kekkai-node as a hardened systemd service with a
# Nix-generated /etc/kekkai/node.toml. Deployment-agnostic: no host name, range or suffix.
# The overlay interface is always `kekkai0` (point annai's resolver module at it, 0010).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.kekkai-node;
  configPath = "/etc/kekkai/node.toml";

  # The module writes only what differs from the daemon's defaults (0016).
  settings = {
    node = {
      private_key_file = cfg.privateKeyFile;
      inherit (cfg) addresses;
    }
    // lib.optionalAttrs (cfg.listenPort != 4802) { listen_port = cfg.listenPort; }
    // lib.optionalAttrs (cfg.mtu != 1280) { inherit (cfg) mtu; };
    peers = lib.mapAttrsToList (
      name: peer:
      {
        inherit name;
        public_key = peer.publicKey;
        inherit (peer) addresses;
      }
      // lib.optionalAttrs (peer.endpoints != [ ]) { inherit (peer) endpoints; }
    ) cfg.peers;
  }
  // lib.optionalAttrs (cfg.logLevel != "info") { log.level = cfg.logLevel; };
  configFile = (pkgs.formats.toml { }).generate "kekkai-node.toml" settings;

  peerType = types.submodule {
    options = {
      publicKey = mkOption {
        type = types.str;
        description = "The peer's public key, standard base64 (`kekkai pubkey`).";
      };
      addresses = mkOption {
        type = types.listOf types.str;
        description = "The peer's overlay addresses, `/32` and `/128` only.";
      };
      endpoints = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Static `host:port` endpoints; DNS names are resolved at start.";
      };
    };
  };
in
{
  options.services.kekkai-node = {
    enable = lib.mkEnableOption "the kekkai overlay node";
    package = lib.mkPackageOption pkgs "kekkai-node" { };
    cliPackage = lib.mkPackageOption pkgs "kekkai" { };

    privateKeyFile = mkOption {
      type = types.str;
      example = "/run/secrets/kekkai-key";
      description = ''
        Path of the private key (one line of base64, `kekkai keygen`), readable by the
        `kekkai` user, typically placed by sops-nix with mode 0400. Never a Nix path: the key
        must not enter the store.
      '';
    };
    listenPort = mkOption {
      type = types.port;
      default = 4802;
      description = "UDP port of the node.";
    };
    addresses = mkOption {
      type = types.listOf types.str;
      example = [
        "10.0.0.1/32"
        "fd00::1/128"
      ];
      description = "This node's overlay addresses: one IPv4 `/32` and one IPv6 `/128`.";
    };
    mtu = mkOption {
      type = types.ints.between 576 1280;
      default = 1280;
      description = "MTU of `kekkai0`; lower it only for a tight underlay (IPv6 needs 1280).";
    };
    peers = mkOption {
      type = types.attrsOf peerType;
      default = { };
      description = "Peers by name; only listed keys complete a handshake.";
    };
    logLevel = mkOption {
      type = types.str;
      default = "info";
      example = "kekkai_io=debug,info";
      description = "`[log] level`, a tracing filter; `RUST_LOG` overrides it.";
    };
    operators = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Users added to the `kekkai` group, allowed to use the control socket.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [
      cfg.package
      cfg.cliPackage
    ];
    environment.etc."kekkai/node.toml".source = configFile;

    # A static user: sops-nix chowns the key at activation, before any unit runs (0018).
    users.users.kekkai = {
      isSystemUser = true;
      group = "kekkai";
    };
    users.groups.kekkai.members = cfg.operators;

    # systemd creates the control socket root:kekkai 0660 and hands it to the daemon (0015).
    systemd.sockets.kekkai-node = {
      description = "kekkai node control socket";
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "/run/kekkai/control.sock" ];
      socketConfig = {
        SocketUser = "root";
        SocketGroup = "kekkai";
        SocketMode = "0660";
      };
    };

    systemd.services.kekkai-node = {
      description = "kekkai overlay node";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "kekkai-node.socket"
      ];
      requires = [ "kekkai-node.socket" ];
      # v0: a configuration change restarts the service at switch (0016).
      restartTriggers = [ configFile ];
      serviceConfig = {
        Type = "notify";
        ExecStart = "${lib.getExe cfg.package} --config ${configPath}";
        Restart = "on-failure";
        User = "kekkai";
        Group = "kekkai";
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        DeviceAllow = [ "/dev/net/tun rw" ];
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];
        ProtectSystem = "strict";
        PrivateTmp = true;
        NoNewPrivileges = true;
      };
    };

    # The daemon owns the interface's addresses and routes.
    networking.dhcpcd.denyInterfaces = [ "kekkai0" ];
  };
}
