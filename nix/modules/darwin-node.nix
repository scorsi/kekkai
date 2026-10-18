# darwinModules.node (0016, 0018, 0022): kekkai-node as a LaunchDaemon with the same options
# as nixosModules.node and a Nix-generated /etc/kekkai/node.toml. The daemon runs as root
# because utun requires it (0018, documented risk); its stderr goes to a file launchd opens.
# The kernel names the overlay interface `utunN` (first free unit, logged at start): the name
# is not stable, so nothing should be pointed at it.
{
  config,
  lib,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.kekkai-node;
  label = "org.nixos.kekkai-node";
  configPath = "/etc/kekkai/node.toml";
  marker = "/var/db/kekkai-node.config";
in
{
  imports = [ ./node-common.nix ];

  options.services.kekkai-node = {
    gid = mkOption {
      type = types.int;
      default = 4802;
      description = "GID of the `kekkai` group (nix-darwin creates groups with a fixed GID).";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [
      cfg.package
      cfg.cliPackage
    ];
    environment.etc."kekkai/node.toml".source = cfg.configFile;

    # The daemon binds /var/run/kekkai/control.sock itself, 0660 root:kekkai (0015).
    users.knownGroups = [ "kekkai" ];
    users.groups.kekkai = {
      inherit (cfg) gid;
      members = cfg.operators;
      description = "kekkai node control socket";
    };

    launchd.daemons.kekkai-node.serviceConfig = {
      Label = label;
      ProgramArguments = [
        (lib.getExe cfg.package)
        "--config"
        configPath
      ];
      RunAtLoad = true;
      KeepAlive = true;
      StandardErrorPath = "/var/log/kekkai-node.log";
    };

    # v0: a configuration change restarts the service at switch (0016). The plist names the
    # stable path, so launchd cannot see the change: compare the generated file instead.
    system.activationScripts.postActivation.text = ''
      if [ "$(cat ${marker} 2>/dev/null)" != "${cfg.configFile}" ]; then
        echo "${cfg.configFile}" > ${marker}
        /bin/launchctl kickstart -k system/${label} 2>/dev/null || true
      fi
    '';
  };
}
