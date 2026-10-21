# v0.2 acceptance (docs/milestones.md): two NixOS nodes on one network with static endpoints
# ping each other over the overlay, and a third node with an unlisted key gets only silence.
# Also checks the daemon's logs and metrics against nisshi's log schema and masu's metric
# convention (ADR 0019). Keys are the public test vectors of docs/spec/vectors/keygen.json.
{
  pkgs,
  module,
  validateLogs,
  validateMetrics,
}:
let
  inherit (pkgs) lib;
  keys = {
    # "rfc7748 alice", "rfc7748 bob", "kekkai 1".
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
  };
  number = {
    a = 1;
    b = 2;
    stranger = 3;
  };
  underlay = n: "192.168.1.${toString number.${n}}";
  overlay4 = n: "10.77.0.${toString number.${n}}";
  overlay6 = n: "fd77::${toString number.${n}}";
  peer = n: {
    publicKey = keys.${n}.public;
    addresses = [
      "${overlay4 n}/32"
      "${overlay6 n}/128"
    ];
    endpoints = [ "${underlay n}:4802" ];
  };
  node = name: peers: {
    imports = [ module ];
    nixpkgs.pkgs = pkgs;
    virtualisation.vlans = [ 1 ];
    networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
      {
        address = underlay name;
        prefixLength = 24;
      }
    ];
    networking.firewall.allowedUDPPorts = [ 4802 ];
    environment.systemPackages = [
      pkgs.tcpdump
      pkgs.curl
    ];
    # Stands in for the sops-nix secret: owned by the service user, mode 0400 (0017).
    environment.etc."kekkai/key" = {
      text = keys.${name}.private + "\n";
      mode = "0400";
      user = "kekkai";
      group = "kekkai";
    };
    users.users.alice.isNormalUser = true;
    users.users.mallory.isNormalUser = true;
    services.kekkai-node = {
      enable = true;
      privateKeyFile = "/etc/kekkai/key";
      addresses = [
        "${overlay4 name}/32"
        "${overlay6 name}/128"
      ];
      peers = lib.genAttrs peers peer;
      operators = [ "alice" ];
      metrics.listen = "127.0.0.1:9480";
    };
  };
in
pkgs.testers.nixosTest {
  name = "kekkai-two-nodes";

  nodes = {
    a = node "a" [ "b" ];
    b = node "b" [ "a" ];
    # Lists b, but b does not list it.
    stranger = node "stranger" [ "b" ];
  };

  testScript = ''
    import json
    from datetime import datetime

    start_all()
    for m in (a, b, stranger):
        # Type=notify: the unit is active only once the daemon sent READY=1.
        m.wait_for_unit("kekkai-node.service")

    with subtest("config check accepts the module's file and refuses an inline secret"):
        out = a.succeed("kekkai-node config check --config /etc/kekkai/node.toml 2>&1")
        assert out.strip().endswith(": ok"), out
        a.succeed(
            "printf '[node]\\nprivate_key = \"${keys.a.private}\"\\n"
            "addresses = [\"10.77.0.1/32\"]\\n' > /tmp/inline.toml"
        )
        out = a.fail("kekkai-node config check --config /tmp/inline.toml 2>&1")
        assert "inline secret" in out, out

    with subtest("control socket is 0660 root:kekkai, outsiders are refused"):
        out = a.succeed("stat -c '%a %U:%G' /run/kekkai/control.sock")
        assert out.strip() == "660 root:kekkai", out
        out = a.succeed("runuser -u alice -- kekkai status --json")
        assert json.loads(out)["node"]["public_key"] == "${keys.a.public}", out
        out = a.fail("runuser -u mallory -- kekkai status --json 2>&1")
        assert "permission denied" in out, out

    with subtest("ping both ways over IPv4 and IPv6 overlay addresses"):
        a.wait_until_succeeds("ping -c 1 -W 1 ${overlay4 "b"}", timeout=60)
        for m, target in (
            (a, "${overlay4 "b"}"),
            (b, "${overlay4 "a"}"),
            (a, "${overlay6 "b"}"),
            (b, "${overlay6 "a"}"),
        ):
            out = m.succeed(f"ping -c 3 -W 2 {target}")
            assert " 0% packet loss" in out, out

    with subtest("status --json shows the name, a direct path, a recent handshake and counters"):
        for m, key, name, endpoint in (
            (a, "${keys.b.public}", "b", "${underlay "b"}:4802"),
            (b, "${keys.a.public}", "a", "${underlay "a"}:4802"),
        ):
            out = m.succeed("kekkai status --json")
            peers = [p for p in json.loads(out)["peers"] if p["public_key"] == key]
            assert len(peers) == 1, out
            p = peers[0]
            assert p["name"] == name, out
            assert p["path"] == "PATH_DIRECT", out
            assert p["endpoint"] == endpoint, out
            for counter in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
                assert int(p.get(counter, "0")) > 0, out
            handshake = datetime.fromisoformat(p["last_handshake"].replace("Z", "+00:00"))
            now = int(m.succeed("date +%s").strip())
            age = now - handshake.timestamp()
            assert -5 < age < 180, f"handshake {age} s old: {out}"

    with subtest("an unlisted key gets no reply"):
        stranger.succeed(
            "tcpdump -Z root -n -U -i eth1 -w /tmp/silence.pcap udp port 4802"
            " >/tmp/tcpdump.log 2>&1 &"
        )
        stranger.wait_until_succeeds("grep -q listening /tmp/tcpdump.log")
        out = stranger.fail("ping -c 3 -W 2 ${overlay4 "b"}")
        assert " 100% packet loss" in out, out
        # Past REKEY_TIMEOUT, so message 1 has been retransmitted at least once.
        stranger.succeed("sleep 6")
        stranger.succeed("pkill -INT tcpdump")
        stranger.wait_until_fails("pgrep tcpdump")
        # The test VLAN is a shared segment (VDE hub): eth1 also sees a <-> b traffic, so
        # every filter names both ends.
        sent = stranger.succeed(
            "tcpdump -n -r /tmp/silence.pcap"
            " 'src host ${underlay "stranger"} and dst host ${underlay "b"} and dst port 4802'"
            " 2>/dev/null"
        )
        assert len(sent.strip().splitlines()) >= 2, sent
        replies = stranger.succeed(
            "tcpdump -n -r /tmp/silence.pcap"
            " 'src host ${underlay "b"} and dst host ${underlay "stranger"}' 2>/dev/null"
        )
        assert replies.strip() == "", replies
        out = stranger.succeed("kekkai status --json")
        peer = json.loads(out)["peers"][0]
        assert peer["path"] == "PATH_NONE" and "last_handshake" not in peer, out

    with subtest("logs pass nisshi's schema v1, metrics pass masu's convention"):
        journal = "journalctl _SYSTEMD_UNIT=kekkai-node.service -o cat"
        for m, other in ((a, "b"), (b, "a")):
            # Empty input passes the validator: the expected event must exist.
            m.wait_until_succeeds(
                f"{journal} | grep -F '\"event\":\"handshake-completed\",\"peer\":\"{other}\"'"
            )
        metrics = "http://127.0.0.1:9480/metrics"
        for m in (a, b, stranger):
            m.succeed(f"{journal} | ${validateLogs} validate --logs")
            m.succeed(f"${validateMetrics} validate --metrics {metrics}")
        for m, other in ((a, "b"), (b, "a")):
            text = m.succeed(f"curl -sf {metrics}")
            ok = f'kekkai_handshakes_total{{peer="{other}",result="ok"}} '
            counts = [int(line[len(ok):]) for line in text.splitlines() if line.startswith(ok)]
            assert counts and counts[0] >= 1, text
            assert f'kekkai_peer_path{{peer="{other}",via="direct"}} 1' in text, text
        # b dropped the stranger's message 1.
        assert "kekkai_dropped_packets_total{" in b.succeed(f"curl -sf {metrics}")
  '';
}
