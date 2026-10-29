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
  cfg = config.services.kekkai-node;
  configPath = "/etc/kekkai/node.toml";
  inherit (cfg) configFile;
in
{
  # Options shared with darwinModules.node.
  imports = [ ./node-common.nix ];

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
      # 0026, spec §4.1: a change of the peer, lighthouse or relay list or of the `[pki]` values
      # reloads (SIGHUP, the daemon re-reads the stable path); the binary or any other section,
      # the presence of `[pki]` and its `max_peers` included, restarts.
      reloadTriggers = [ configFile ];
      restartTriggers = [
        cfg.package
        cfg.restartFingerprint
      ];
      serviceConfig = {
        Type = "notify";
        ExecStart = "${lib.getExe cfg.package} --config ${configPath}";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
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
