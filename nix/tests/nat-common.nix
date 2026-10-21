# Shared pieces of the v0.4 and v0.5 nixosTests (docs/milestones.md): nftables NAT routers
# (`masquerade`, a cone NAT for ADR 0020, or `masquerade fully-random`, a symmetric one), a
# public lighthouse, a public relay and nodes that know no endpoint of each other. Addresses
# are documentation ranges; keys are the public test vectors of
# docs/spec/vectors/keygen.json.
{
  pkgs,
  nodeModule,
  lighthouseModule,
  relayModule ? null,
}:
let
  inherit (pkgs) lib;
in
rec {
  keys = {
    # "rfc7748 alice", "rfc7748 bob", "kekkai 1", "kekkai 2".
    a = {
      private = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
      public = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    };
    b = {
      private = "XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=";
      public = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
    };
    stranger = {
      private = "GNU2HJn9qnZ6rF4bfEuou+wunl8+u9RnTOa+9d/S1Vs=";
      public = "ta5DN5JdcLfn//qzn1vkBX+LgBEF698PsB10l9cpxxo=";
    };
    lighthouse = {
      private = "4AjQ/Jh90CPykTRR/N+lFlQIUHWC1qeWnb+Wws8/3UE=";
      public = "HZekfj15ogjJcYSkT1dubjBB7Twk+3P6/n+fHFl14Ho=";
    };
    # The "unclamped input" vector, clamped.
    relay = {
      private = "uH47CkiK1r4jwwG3lMtZe7O+mNwQdi7TF4+WS3sUK1Q=";
      public = "Ch5PtKcJ7vA1o8/evc8w7xJCKf0CRfJiLj+ZwYTkSgE=";
    };
  };
  number = {
    a = 1;
    b = 2;
    stranger = 3;
  };
  overlay4 = n: "10.77.0.${toString number.${n}}";
  overlay6 = n: "fd77::${toString number.${n}}";
  # vlan 1 is the public network.
  lighthouseIp = "192.0.2.10";
  lighthouseSocket = "/run/kekkai-lighthouse/control.sock";
  relaySocket = "/run/kekkai-relay/control.sock";
  # `masquerade fully-random`: a new random public port per flow, a symmetric NAT.
  symmetric = "masquerade fully-random";

  # Only the addresses a test gives, IPv4 only; eth0 (the driver's) stays unconfigured.
  interfaces = ifs: {
    networking.useDHCP = false;
    networking.interfaces = lib.mapAttrs (_: address: {
      ipv4.addresses = lib.mkForce (
        lib.optional (address != null) {
          inherit address;
          prefixLength = 24;
        }
      );
      ipv6.addresses = lib.mkForce [ ];
    }) ifs;
  };

  # The builder runs every VM of a test at once on 8 GiB shared with other services: size
  # each one (384 MiB was the qemu-vm default for years) and keep the closure lean.
  size = memorySize: {
    virtualisation = {
      inherit memorySize;
      cores = 1;
    };
    documentation.enable = false;
    # The test instrumentation waits 300 s for a device (DefaultDeviceTimeoutSec in
    # nixos/modules/testing/test-instrumentation.nix); past it, dev-hvc0.device fails and
    # backdoor.service, which requires it, never starts. A slow boot gets 900 s.
    systemd.settings.Manager.DefaultDeviceTimeoutSec = lib.mkForce 900;
  };

  # eth1 on the public vlan 1, eth2 on `lan`: masquerade out of eth1. Another `masquerade`
  # statement applies to the LAN's datagrams only, so that the router's own (the nat-relayed
  # stranger's) keep their source port.
  router =
    {
      public,
      lan,
      inside,
      masquerade ? "masquerade",
    }:
    let
      lanNet = lib.concatStringsSep "." (lib.init (lib.splitString "." inside) ++ [ "0" ]);
      match = lib.optionalString (masquerade != "masquerade") "ip saddr ${lanNet}/24 ";
    in
    {
      imports = [
        (size 384)
        (interfaces {
          eth1 = public;
          eth2 = inside;
        })
      ];
      virtualisation.vlans = [
        1
        lan
      ];
      boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
      # Like a real NAT router, drop unsolicited datagrams to itself (input only; forwarding
      # is not filtered). Accepted, each one confirmed a conntrack entry that made masquerade
      # map the inside host's later flow towards that sender to another port: a peer's
      # datagrams arriving before the inside host's own then blocked the hole punch for as
      # long as they were retransmitted (spec §13.2).
      networking.firewall.enable = true;
      networking.nftables = {
        enable = true;
        tables.nat = {
          family = "ip";
          content = ''
            chain postrouting {
              type nat hook postrouting priority srcnat; policy accept;
              ${match}oifname "eth1" ${masquerade}
            }
          '';
        };
      };
    };

  lighthouse = {
    imports = [
      lighthouseModule
      (size 384)
      (interfaces { eth1 = lighthouseIp; })
    ];
    nixpkgs.pkgs = pkgs;
    virtualisation.vlans = [ 1 ];
    networking.firewall.allowedUDPPorts = [ 4800 ];
    environment.systemPackages = [
      pkgs.jq
      pkgs.curl
    ];
    environment.etc."kekkai/lighthouse-key" = {
      text = keys.lighthouse.private + "\n";
      mode = "0400";
      user = "kekkai-lighthouse";
      group = "kekkai-lighthouse";
    };
    services.kekkai-lighthouse = {
      enable = true;
      privateKeyFile = "/etc/kekkai/lighthouse-key";
      # The stranger is not listed.
      peers =
        lib.genAttrs
          [
            "a"
            "b"
          ]
          (n: {
            publicKey = keys.${n}.public;
          });
      metrics.listen = "127.0.0.1:9481";
    };
  };

  # The relay service, beside the lighthouse on its public VM (0005: roles, not hosts).
  relay = {
    imports = [ relayModule ];
    networking.firewall.allowedUDPPorts = [ 4801 ];
    environment.systemPackages = [ pkgs.tcpdump ];
    environment.etc."kekkai/relay-key" = {
      text = keys.relay.private + "\n";
      mode = "0400";
      user = "kekkai-relay";
      group = "kekkai-relay";
    };
    services.kekkai-relay = {
      enable = true;
      privateKeyFile = "/etc/kekkai/relay-key";
      # The stranger is not listed.
      peers =
        lib.genAttrs
          [
            "a"
            "b"
          ]
          (n: {
            publicKey = keys.${n}.public;
          });
      metrics.listen = "127.0.0.1:9482";
    };
  };

  # The kekkai-node service with no static endpoint: everything comes from the lighthouse.
  # Without network settings, so that a router can also run one (the nat-direct stranger).
  kekkaiNode =
    {
      name,
      peers,
      port ? 4802,
      relay ? false,
    }:
    {
      imports = [ nodeModule ];
      nixpkgs.pkgs = pkgs;
      networking.firewall.allowedUDPPorts = [ port ];
      environment.systemPackages = [
        pkgs.jq
        pkgs.curl
        pkgs.tcpdump
      ];
      environment.etc."kekkai/key" = {
        text = keys.${name}.private + "\n";
        mode = "0400";
        user = "kekkai";
        group = "kekkai";
      };
      services.kekkai-node = {
        enable = true;
        privateKeyFile = "/etc/kekkai/key";
        listenPort = port;
        addresses = [
          "${overlay4 name}/32"
          "${overlay6 name}/128"
        ];
        peers = lib.genAttrs peers (n: {
          publicKey = keys.${n}.public;
          addresses = [
            "${overlay4 n}/32"
            "${overlay6 n}/128"
          ];
        });
        lighthouses = [
          {
            publicKey = keys.lighthouse.public;
            endpoint = "${lighthouseIp}:4800";
          }
        ];
        relays = lib.optional relay {
          publicKey = keys.relay.public;
          endpoint = "${lighthouseIp}:4801";
        };
        metrics.listen = "127.0.0.1:9480";
      };
    };

  # A node VM on its own LAN.
  node =
    {
      name,
      vlans,
      ifs,
      gateway,
      peers,
      port ? 4802,
      relay ? false,
    }:
    {
      imports = [
        (kekkaiNode {
          inherit
            name
            peers
            port
            relay
            ;
        })
        (size 512)
        (interfaces ifs)
      ];
      virtualisation.vlans = vlans;
      networking.defaultGateway = {
        address = gateway;
        interface = "eth1";
      };
    };

  # Python helpers of both test scripts.
  script = ''
    import json

    LIGHTHOUSE_SOCKET = "${lighthouseSocket}"
    RELAY_SOCKET = "${relaySocket}"


    def boot(*machines):
        """Start the VMs one at a time, in order: all at once starve a small builder."""
        for m in machines:
            m.start()
            m.wait_for_unit("multi-user.target")


    def status(m, socket=None):
        extra = f" --socket {socket}" if socket else ""
        return json.loads(m.succeed("kekkai status --json" + extra))


    def peer(m, key):
        peers = [p for p in status(m)["peers"] if p["public_key"] == key]
        assert len(peers) == 1, peers
        return peers[0]


    def jq_peer(key, condition):
        """A shell check on the node's status of peer `key`, for wait_until_succeeds."""
        select = f'.peers[] | select(.public_key == "{key}")'
        return f"kekkai status --json | jq -e '{select} | {condition}'"
  '';
}
