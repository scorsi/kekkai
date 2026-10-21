# v0.3 acceptance (docs/milestones.md, ADR 0011, spec §15): the per-peer inbound firewall.
# a serves DNS-like udp/53 and tcp/53 to every peer; b lets a reach tcp/22 and nothing else,
# and c nothing (default deny). The host firewall trusts kekkai0, so every refusal seen here
# is kekkai's. Keys are the public test vectors of docs/spec/vectors/keygen.json.
{ pkgs, module }:
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
    c = {
      private = "GNU2HJn9qnZ6rF4bfEuou+wunl8+u9RnTOa+9d/S1Vs=";
      public = "ta5DN5JdcLfn//qzn1vkBX+LgBEF698PsB10l9cpxxo=";
    };
  };
  number = {
    a = 1;
    b = 2;
    c = 3;
  };
  underlay = n: "192.168.1.${toString number.${n}}";
  overlay4 = n: "10.77.0.${toString number.${n}}";
  overlay6 = n: "fd77::${toString number.${n}}";
  # allow.<node>.<peer>: what <peer> may reach on <node>.
  allow = {
    a = {
      b = dns;
      c = dns;
    };
    b = {
      a = [ "tcp/22" ];
      c = [ ];
    };
    c = {
      a = [ ];
      b = [ ];
    };
  };
  dns = [
    "udp/53"
    "tcp/53"
  ];
  node = name: {
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
    # Only kekkai filters the tunnel.
    networking.firewall.trustedInterfaces = [ "kekkai0" ];
    environment.systemPackages = [
      pkgs.socat
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
      addresses = [
        "${overlay4 name}/32"
        "${overlay6 name}/128"
      ];
      peers = lib.mapAttrs (peer: rules: {
        publicKey = keys.${peer}.public;
        addresses = [
          "${overlay4 peer}/32"
          "${overlay6 peer}/128"
        ];
        endpoints = [ "${underlay peer}:4802" ];
        allowInbound = rules;
      }) allow.${name};
    };
  };
in
pkgs.testers.nixosTest {
  name = "kekkai-firewall";

  nodes = {
    a = node "a";
    b = node "b";
    c = node "c";
  };

  testScript = ''
    import json
    from typing import Any

    def peer_status(m: Any, key: str) -> dict[str, Any]:
        out = m.succeed("kekkai status --json")
        status = json.loads(out)
        peers = [p for p in status["peers"] if p["public_key"] == key]
        assert len(peers) == 1, out
        print(out)
        return peers[0]

    def drops(m: Any, key: str) -> int:
        return int(peer_status(m, key).get("firewall_drops", "0"))

    def tcp(target: str, port: int) -> str:
        return f"socat -u TCP:{target}:{port},connect-timeout=4 - 2>&1"

    # One request datagram: socat's default UDP shut-null would follow it with an empty
    # one, which a UDP-LISTEN fork parent may take before its child connects, forking a
    # second child that answers too.
    def udp(target: str, port: int) -> str:
        return f"echo query | socat -T 4 - UDP:{target}:{port},shut-none 2>&1"

    start_all()
    for m in (a, b, c):
        m.wait_for_unit("kekkai-node.service")
    # TCP services answer their port number; dual stack.
    for port in (22, 8443):
        b.succeed(
            f"socat TCP6-LISTEN:{port},ipv6only=0,fork,reuseaddr SYSTEM:'echo b{port}'"
            " >/dev/null 2>&1 &"
        )
    a.succeed(
        "socat UDP6-LISTEN:53,ipv6only=0,fork,reuseaddr SYSTEM:'echo a53' >/dev/null 2>&1 &"
    )
    a.succeed(
        "socat TCP6-LISTEN:53,ipv6only=0,fork,reuseaddr SYSTEM:'echo a53' >/dev/null 2>&1 &"
    )

    with subtest("the module writes allow_inbound and config check accepts it"):
        out = b.succeed("cat /etc/kekkai/node.toml; kekkai-node config check 2>&1")
        print(out)
        assert 'allow_inbound = ["tcp/22"]' in out and out.strip().endswith(": ok"), out

    with subtest("ICMP always passes, also from a peer with no rule"):
        for m, target in ((a, "${overlay4 "b"}"), (c, "${overlay4 "b"}"), (c, "${overlay6 "a"}")):
            m.wait_until_succeeds(f"ping -c 1 -W 1 {target}", timeout=60)
            out = m.succeed(f"ping -c 3 -W 2 {target}")
            print(out)
            assert " 0% packet loss" in out, out

    with subtest("a reaches tcp/22 on b over IPv4 and IPv6"):
        for target in ("${overlay4 "b"}", "[${overlay6 "b"}]"):
            out = a.wait_until_succeeds(tcp(target, 22), timeout=30)
            print(out)
            assert out.strip() == "b22", out

    with subtest("another port from a is dropped: timeout, no reset over the tunnel"):
        a.succeed(
            "tcpdump -Z root -n -U -i kekkai0 -w /tmp/8443.pcap tcp port 8443"
            " >/tmp/tcpdump.log 2>&1 &"
        )
        a.wait_until_succeeds("grep -q listening /tmp/tcpdump.log")
        before = drops(b, "${keys.a.public}")
        out = a.fail(tcp("${overlay4 "b"}", 8443))
        print(out)
        assert "b8443" not in out and "refused" not in out.lower(), out
        a.succeed("pkill -INT tcpdump")
        a.wait_until_fails("pgrep tcpdump")
        syns = a.succeed("tcpdump -n -r /tmp/8443.pcap 'tcp[tcpflags] & tcp-syn != 0' 2>/dev/null")
        print(syns)
        assert len(syns.strip().splitlines()) >= 1, syns
        resets = a.succeed("tcpdump -n -r /tmp/8443.pcap 'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null")
        print(resets)
        assert resets.strip() == "", resets
        after = drops(b, "${keys.a.public}")
        assert after > before, f"firewall_drops for a on b: {before} -> {after}"

    with subtest("the same tcp/22 from another peer is dropped and counted"):
        out = c.fail(tcp("${overlay4 "b"}", 22))
        print(out)
        assert "b22" not in out, out
        n = drops(b, "${keys.c.public}")
        assert n > 0, f"firewall_drops for c on b: {n}"
        # The drop is the firewall's, not a missing session.
        p = peer_status(b, "${keys.c.public}")
        assert p["path"] == "PATH_DIRECT", p

    with subtest("UDP and TCP requests to a's allowed service get their replies (flow table)"):
        for m in (b, c):
            out = m.succeed(udp("${overlay4 "a"}", 53))
            print(out)
            assert out.strip() == "a53", out
            out = m.succeed(tcp("${overlay4 "a"}", 53))
            print(out)
            assert out.strip() == "a53", out
        # b has no rule for a's udp/53 replies: they passed as replies to b's own flow.
        assert drops(b, "${keys.a.public}") == after, "no new drop for a's replies"
        out = b.succeed("kekkai status --json")
        print(out)
        fw = json.loads(out)["firewall"]
        assert int(fw.get("udp_flows", "0")) >= 1 and int(fw["udp_flows_max"]) == 4096, out
        # a unsolicited UDP from a to b is not a reply and has no rule.
        b.succeed(
            "socat UDP6-LISTEN:5353,ipv6only=0,fork,reuseaddr SYSTEM:'echo b5353'"
            " >/dev/null 2>&1 &"
        )
        out = a.succeed(udp("${overlay4 "b"}", 5353) + " || true")
        print(out)
        assert "b5353" not in out, out

    with subtest("the rules survive a service restart"):
        b.succeed("systemctl restart kekkai-node.service")
        b.wait_for_unit("kekkai-node.service")
        p = peer_status(b, "${keys.a.public}")
        assert p.get("allow_inbound") == ["tcp/22"], p
        assert int(p.get("firewall_drops", "0")) == 0, p
        out = a.wait_until_succeeds(tcp("${overlay4 "b"}", 22), timeout=60)
        print(out)
        assert out.strip() == "b22", out
        out = a.fail(tcp("${overlay4 "b"}", 8443))
        print(out)
        assert "b8443" not in out, out
        n = drops(b, "${keys.a.public}")
        assert n > 0, f"firewall_drops for a on b after restart: {n}"
  '';
}
