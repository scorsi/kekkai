# v0.5 acceptance (docs/milestones.md, `relay-upgrade`): A and B start relayed behind
# symmetric NATs; the routers then become cone NATs (plain `masquerade`, conntrack
# flushed) and the periodic direct retry (spec §12.3, every 60 s) moves both to a direct
# path within 90 s. Five VMs, as nat-relayed without the stranger.
{
  pkgs,
  nodeModule,
  lighthouseModule,
  relayModule,
}:
let
  common = import ./nat-common.nix {
    inherit
      pkgs
      nodeModule
      lighthouseModule
      relayModule
      ;
  };
  inherit (common) keys overlay4;
  router = args: {
    imports = [ (common.router (args // { masquerade = common.symmetric; })) ];
    environment.systemPackages = [ pkgs.conntrack-tools ];
  };
in
pkgs.testers.nixosTest {
  name = "kekkai-relay-upgrade";

  nodes = {
    lighthouse.imports = [
      common.lighthouse
      common.relay
    ];
    routera = router {
      public = "192.0.2.1";
      lan = 2;
      inside = "10.1.0.1";
    };
    routerb = router {
      public = "192.0.2.2";
      lan = 3;
      inside = "10.2.0.1";
    };
    a = common.node {
      name = "a";
      vlans = [ 2 ];
      ifs.eth1 = "10.1.0.2";
      gateway = "10.1.0.1";
      peers = [ "b" ];
      relay = true;
    };
    b = common.node {
      name = "b";
      vlans = [ 3 ];
      ifs.eth1 = "10.2.0.2";
      gateway = "10.2.0.1";
      peers = [ "a" ];
      relay = true;
    };
  };

  testScript = ''
    import time

    ${common.script}

    boot(lighthouse, routera, routerb, a, b)
    lighthouse.wait_for_unit("kekkai-lighthouse.service")
    lighthouse.wait_for_unit("kekkai-relay.service")
    for m in (a, b):
        m.wait_for_unit("kekkai-node.service")
        m.wait_until_succeeds(
            "kekkai status --json | jq -e '.lighthouses[0].state == \"SESSION_STATE_CONNECTED\""
            " and .relays[0].state == \"SESSION_STATE_CONNECTED\"'",
            timeout=60,
        )

    with subtest("relayed behind symmetric NATs"):
        a.succeed("ping -c 1 -W 8 ${overlay4 "b"}")
        a.wait_until_succeeds(jq_peer("${keys.b.public}", '.path == "PATH_RELAYED"'), timeout=10)
        b.wait_until_succeeds(jq_peer("${keys.a.public}", '.path == "PATH_RELAYED"'), timeout=10)

    with subtest("cone NATs: both direct within 90 s"):
        # Traffic keeps flowing over the relay meanwhile; it is not needed for the retry.
        a.succeed("ping -i 0.5 -W 1 ${overlay4 "b"} >/dev/null 2>&1 &")
        for r, lan in ((routera, "10.1.0.0"), (routerb, "10.2.0.0")):
            r.succeed(
                "nft flush chain ip nat postrouting"
                f" && nft add rule ip nat postrouting ip saddr {lan}/24 oifname eth1 masquerade"
                " && conntrack -F"
            )
        switched = time.monotonic()
        direct = '.path == "PATH_DIRECT"'
        a.wait_until_succeeds(jq_peer("${keys.b.public}", direct), timeout=90)
        left = max(1, int(90 - (time.monotonic() - switched)))
        b.wait_until_succeeds(jq_peer("${keys.a.public}", direct), timeout=left)
        assert peer(a, "${keys.b.public}")["endpoint"].startswith("192.0.2.2:")
        assert peer(b, "${keys.a.public}")["endpoint"].startswith("192.0.2.1:")
        a.succeed("pkill ping")
        out = b.succeed("ping -c 3 -W 2 ${overlay4 "a"}")
        assert " 0% packet loss" in out, out
  '';
}
