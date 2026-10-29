# Options shared by nixosModules.node and darwinModules.node (0016, 0022): they mirror the
# node file one to one, and the module writes only what differs from the daemon's defaults.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.kekkai-node;

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
      // lib.optionalAttrs (peer.allowInbound != [ ]) { allow_inbound = peer.allowInbound; }
    ) cfg.peers;
  }
  // lib.optionalAttrs (cfg.lighthouses != [ ]) {
    lighthouses = map (l: {
      public_key = l.publicKey;
      inherit (l) endpoint;
    }) cfg.lighthouses;
  }
  // lib.optionalAttrs (cfg.relays != [ ]) {
    relays = map (r: {
      public_key = r.publicKey;
      inherit (r) endpoint;
    }) cfg.relays;
  }
  // lib.optionalAttrs (cfg.firewall.udpFlowsMax != 4096) {
    firewall.udp_flows_max = cfg.firewall.udpFlowsMax;
  }
  // lib.optionalAttrs (cfg.logLevel != "info") { log.level = cfg.logLevel; }
  // lib.optionalAttrs (cfg.metrics.listen != null) { metrics.listen = cfg.metrics.listen; }
  // lib.optionalAttrs (cfg.pki != null) {
    pki = {
      ca_keys = cfg.pki.caKeys;
      inherit (cfg.pki) certificate prefixes;
    }
    // lib.optionalAttrs (cfg.pki.revoked != [ ]) { inherit (cfg.pki) revoked; }
    // lib.optionalAttrs (cfg.pki.maxPeers != 256) { max_peers = cfg.pki.maxPeers; };
  };

  # Spec §4.1: a reload applies the lists and the `[pki]` values; any other change, the
  # presence of `[pki]` and its `max_peers` included, needs a restart.
  restartSettings =
    removeAttrs settings [
      "peers"
      "lighthouses"
      "relays"
      "pki"
    ]
    // lib.optionalAttrs (cfg.pki != null) { pki.max_peers = cfg.pki.maxPeers; };

  pkiType = types.submodule {
    options = {
      caKeys = mkOption {
        type = types.addCheck (types.listOf types.str) (l: l != [ ] && builtins.length l <= 2) // {
          description = "list of one or two CA keys";
        };
        description = "Trusted CA public keys (Ed25519, standard base64), one or two for a rotation.";
      };
      certificate = mkOption {
        type = types.str;
        description = ''
          This node's certificate, standard base64 on one line (`kekkai cert sign`). Public,
          so it is written inline and a renewal reloads; its addresses must be exactly
          `addresses`.
        '';
      };
      revoked = mkOption {
        type = types.listOf (types.strMatching "(key|cert):[A-Za-z0-9+/]{43}=");
        default = [ ];
        description = ''
          Deny list (spec §4.3): `key:` a node's public key, `cert:` a certificate
          fingerprint, each in base64. A change reloads and cuts the matching sessions.
        '';
      };
      prefixes = mkOption {
        type = types.listOf types.str;
        example = [
          "10.0.0.0/16"
          "fd00::/64"
        ];
        description = ''
          Overlay prefixes, no host bit set: certificate addresses must lie inside one, and
          each is routed to the tunnel (spec §4.4).
        '';
      };
      maxPeers = mkOption {
        type = types.ints.positive;
        default = 256;
        description = "Bound of the certificate peer table (spec §4.4); a change restarts.";
      };
    };
  };

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
      allowInbound = mkOption {
        type = types.listOf (types.strMatching "any|(tcp|udp)/([0-9]+|\\*)");
        default = [ ];
        example = [
          "tcp/22"
          "udp/53"
        ];
        description = ''
          What this peer may reach on this node through the tunnel (0011): `tcp/PORT`,
          `udp/PORT`, `tcp/*`, `udp/*` or `any`. Default deny: with an empty list the peer
          only gets ICMP and the replies to flows this node opened.
        '';
      };
    };
  };
  # A lighthouse or relay entry (`role`, default port).
  serviceType =
    role: port:
    types.submodule {
      options = {
        publicKey = mkOption {
          type = types.str;
          description = "The ${role}'s public key, standard base64.";
        };
        endpoint = mkOption {
          type = types.str;
          example = "${role}.example.org:${toString port}";
          description = "`host:port` of the ${role}; a DNS name is resolved at start.";
        };
      };
    };
  # A list from the start, one element supported in v0 (0005, 0012, 0014).
  atMostOne =
    role: port:
    types.addCheck (types.listOf (serviceType role port)) (l: builtins.length l <= 1)
    // {
      description = "list of at most one ${role}";
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
        daemon, typically placed by sops-nix with mode 0400. Never a Nix path: the key must
        not enter the store.
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
      description = "MTU of the overlay interface; lower it only for a tight underlay (IPv6 needs 1280).";
    };
    peers = mkOption {
      type = types.attrsOf peerType;
      default = { };
      description = "Peers by name; only listed keys complete a handshake.";
    };
    lighthouses = mkOption {
      type = atMostOne "lighthouse" 4800;
      default = [ ];
      description = ''
        Lighthouses this node registers with and queries to find peers without static
        endpoints (0012, 0013). v0 supports one.
      '';
    };
    relays = mkOption {
      type = atMostOne "relay" 4801;
      default = [ ];
      description = ''
        Relays this node falls back to when no direct path to a peer completes within 3 s
        (0013, 0014). v0 supports one.
      '';
    };
    firewall.udpFlowsMax = mkOption {
      type = types.ints.positive;
      default = 4096;
      description = "Bound of the inbound firewall's UDP flow and fragment table (spec §15).";
    };
    logLevel = mkOption {
      type = types.str;
      default = "info";
      example = "kekkai_io=debug,info";
      description = "`[log] level`, a tracing filter; `RUST_LOG` overrides it.";
    };
    metrics.listen = mkOption {
      # Loopback only (masu's metric convention): the type refuses any other address.
      type = types.nullOr (types.strMatching "(127\\.0\\.0\\.1|\\[::1]):[0-9]+");
      default = null;
      example = "127.0.0.1:9480";
      description = ''
        Loopback address of the `GET /metrics` listener (0019), `127.0.0.1:PORT` or
        `[::1]:PORT`; `null` runs no listener.
      '';
    };
    pki = mkOption {
      type = types.nullOr pkiType;
      default = null;
      description = ''
        `[pki]` (ADR 0034, spec §4.2 to §4.4): admits peers listed nowhere by a certificate of
        a trusted CA. `null` keeps the v0 identity function. Turning it on or off restarts the
        daemon; its values reload.
      '';
    };
    operators = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Users added to the `kekkai` group, allowed to use the control socket.";
    };
    configFile = mkOption {
      type = types.path;
      internal = true;
      readOnly = true;
      default = (pkgs.formats.toml { }).generate "kekkai-node.toml" settings;
      description = "The generated node file, installed as /etc/kekkai/node.toml.";
    };
    restartFingerprint = mkOption {
      type = types.str;
      internal = true;
      readOnly = true;
      default = builtins.hashString "sha256" (builtins.toJSON restartSettings);
      description = ''
        Hash of the sections a reload does not apply (spec §4.1): when it changes, the
        service restarts instead of reloading (0026).
      '';
    };
  };
}
