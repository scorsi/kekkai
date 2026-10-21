# v0.4 acceptance (docs/milestones.md, `roaming`): A and B first connect through their LAN
# addresses (the local endpoints they registered with the public lighthouse) behind one
# cone NAT; A then moves to another network behind another NAT. Its local addresses change,
# so at its next lighthouse keepalive it re-registers and rediscovers B (spec §12.5 rule 3):
# within 30 s both show a new direct endpoint, each the other's NAT address, and ping
# resumes. B listens on another port than A so that one masquerade keeps both ports.
{
  pkgs,
  nodeModule,
  lighthouseModule,
}:
let
  common = import ./nat-common.nix { inherit pkgs nodeModule lighthouseModule; };
  inherit (common) keys overlay4;
in
pkgs.testers.nixosTest {
  name = "kekkai-roaming";

  nodes = {
    lighthouse = common.lighthouse;
    home = common.router {
      public = "192.0.2.1";
      lan = 2;
      inside = "10.2.0.1";
    };
    away = common.router {
      public = "192.0.2.2";
      lan = 3;
      inside = "10.1.0.1";
    };
    # eth1 on the home LAN, eth2 on the away LAN, unconfigured until the move.
    a = common.node {
      name = "a";
      vlans = [
        2
        3
      ];
      ifs = {
        eth1 = "10.2.0.2";
        eth2 = null;
      };
      gateway = "10.2.0.1";
      peers = [ "b" ];
    };
    b = common.node {
      name = "b";
      vlans = [ 2 ];
      ifs.eth1 = "10.2.0.3";
      gateway = "10.2.0.1";
      peers = [ "a" ];
      port = 4803;
    };
  };

  testScript = ''
    ${common.script}
    import time

    start_all()
    lighthouse.wait_for_unit("kekkai-lighthouse.service")
    for m in (a, b):
        m.wait_for_unit("kekkai-node.service")
    lighthouse.wait_until_succeeds(
        f"kekkai status --json --socket {LIGHTHOUSE_SOCKET}"
        " | jq -e '[.registrations[].name] | sort == [\"a\", \"b\"]'",
        timeout=60,
    )

    with subtest("on a shared LAN, A and B connect through their local endpoints"):
        a.wait_until_succeeds("ping -c 1 -W 1 ${overlay4 "b"}", timeout=60)
        a.wait_until_succeeds(jq_peer("${keys.b.public}", '.endpoint == "10.2.0.3:4803"'), timeout=30)
        b.wait_until_succeeds(jq_peer("${keys.a.public}", '.endpoint == "10.2.0.2:4802"'), timeout=30)

    with subtest("A moves behind another NAT: both learn a new endpoint within 30 s"):
        a.succeed(
            "ip addr flush dev eth1 && ip link set eth1 down"
            " && ip link set eth2 up && ip addr add 10.1.0.2/24 dev eth2"
            " && ip route replace default via 10.1.0.1 dev eth2"
        )
        moved = time.monotonic()
        a.wait_until_succeeds(
            jq_peer(
                "${keys.b.public}",
                '.path == "PATH_DIRECT" and (.endpoint | startswith("192.0.2.1:"))',
            ),
            timeout=30,
        )
        left = max(1, int(30 - (time.monotonic() - moved)))
        b.wait_until_succeeds(
            jq_peer(
                "${keys.a.public}",
                '.path == "PATH_DIRECT" and (.endpoint | startswith("192.0.2.2:"))',
            ),
            timeout=left,
        )
        left = max(1, int(30 - (time.monotonic() - moved)))
        a.wait_until_succeeds("ping -c 1 -W 1 ${overlay4 "b"}", timeout=left)
        elapsed = time.monotonic() - moved
        assert elapsed < 30, f"recovered after {elapsed:.1f} s"
        out = b.succeed("ping -c 3 -W 2 ${overlay4 "a"}")
        assert " 0% packet loss" in out, out
  '';
}
