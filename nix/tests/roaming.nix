# v0.4 acceptance (docs/milestones.md, `roaming`): A and B first connect through their LAN
# addresses (the local endpoints they registered with the public lighthouse) behind one
# cone NAT; A then moves to another network behind another NAT. Its local addresses change,
# so at its next register (spec §13.1) it re-registers and rediscovers B (§12.5 rule 3):
# within 30 s both show a new direct endpoint, each the other's NAT address, and ping
# resumes. B listens on another port than A so that one masquerade keeps both ports.
#
# Worst case: the move lands just after the lighthouse answered a register, so nothing is
# pending and the next register tick finds it 25 s later (a move before that answer loses
# it and the 15 s "new handshake" timer finds it first); the handshake through the
# lighthouse's answer and punch then takes a few round trips. The 30 s bound is checked on
# A's own clock, in one guest command: from just before the move to the first instant at
# which A reports B's new direct endpoint AND a ping to B succeeds. That ping's reply proves
# B's transition too: B answered A's new NAT address, which an authenticated packet from it
# sets as B's endpoint (spec §12.4); B's status is checked right after. The command's
# timeout is only a watchdog.
#
# Then (v0.6 finding 4) A changes its address on the away LAN, which keeps its public port:
# its keepalive on the change of its local endpoints (§12.4) reopens the way for B's traffic
# within 5 s, measured on B's clock from before the change, with B's session unchanged.
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
    away = {
      imports = [
        (common.router {
          public = "192.0.2.2";
          lan = 3;
          inside = "10.1.0.1";
        })
      ];
      environment.systemPackages = [ pkgs.conntrack-tools ];
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
    from datetime import datetime

    boot(lighthouse, home, away, a, b)
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

    with subtest("A moves behind another NAT: endpoints and traffic recover within 30 s"):
        a_sees_b = jq_peer(
            "${keys.b.public}",
            '.path == "PATH_DIRECT" and (.endpoint | startswith("192.0.2.1:"))',
        )
        out = a.succeed(
            "moved=$(date +%s.%N) && ip addr flush dev eth1 && ip link set eth1 down"
            " && ip link set eth2 up && ip addr add 10.1.0.2/24 dev eth2"
            " && ip route replace default via 10.1.0.1 dev eth2"
            f" && until {a_sees_b} >/dev/null && ping -c 1 -W 1 ${overlay4 "b"} >/dev/null;"
            " do sleep 0.2; done"
            ' && echo "$moved $(date +%s.%N)"',
            timeout=120,
        )
        moved, recovered = map(float, out.split())
        took = recovered - moved
        assert 0 < took < 30, f"recovered after {took:.1f} s"
        b.succeed(
            jq_peer(
                "${keys.a.public}",
                '.path == "PATH_DIRECT" and (.endpoint | startswith("192.0.2.2:"))',
            )
        )
        out = b.succeed("ping -c 3 -W 2 ${overlay4 "a"}")
        assert " 0% packet loss" in out, out

    with subtest("A changes its address behind the same NAT: traffic from B resumes within 5 s"):
        # v0.6 finding 4: the peer of a node that changes address must be found again at once
        # when it is reachable at its unchanged endpoint. B is behind `home`, which drops
        # datagrams from any port of `away` but the one B sent to: so `away` keeps A's public
        # port, its conntrack table flushed as a NAT that lost the old mapping, and B's pings
        # to that port are dropped by `away` until A itself sends from its new address.
        # Nothing of A's own goes to B for about 15 s (just after A's register and a ping from
        # B: no passive keepalive due, register tick and "new handshake" timer later), except
        # its keepalive on the change of its local endpoints (spec §12.4), sent at the next
        # poll. The daemon is stopped while the address and route change, so that the poll
        # sees only the final state (a keepalive with no route would be lost, ADR 0032).
        # Timers run on while it is stopped: the time is measured from before the stop, and a
        # new handshake (A's "new handshake" timer, a rediscovery), which would also reopen
        # `away`, fails the subtest: B's session must be the same before and after.
        old = peer(b, "${keys.a.public}")["endpoint"]
        assert old == "192.0.2.2:4802", old

        def age(field):
            """Age on B's clock of a timestamp of B's status of A."""
            t = peer(b, "${keys.a.public}")[field]
            return float(b.succeed("date +%s.%N")) - datetime.fromisoformat(t).timestamp()

        # Let the session of subtest 2 settle first: its move may still bring a handshake,
        # unrelated to this change (a rediscovery or punch deferred by the REKEY_TIMEOUT
        # pacing, §7.9, §12.5, starts at most 5 s after the last message 1). Quiet once B's
        # last handshake with A is 2 x REKEY_TIMEOUT old: past that deferral and its answer;
        # the 3 s DIRECT_PATH_TIMEOUT window is within it, and the 15 s "new handshake" timer
        # is not armed (B's pings are answered).
        retry(lambda _: age("last_handshake") > 10, timeout_seconds=60)
        lighthouse.wait_until_succeeds(
            f"kekkai status --json --socket {LIGHTHOUSE_SOCKET} | jq -e"
            " '.registrations[] | select(.name == \"a\") | .last_seen | rtrimstr(\"s\") | tonumber < 1'",
            timeout=60,
        )
        b.succeed("ping -c 1 -W 1 ${overlay4 "a"}")

        # A new handshake always takes a new receiver index; last_handshake is not compared, it is
        # rebuilt from the monotonic clock at each status call and drifts by nanoseconds.
        def session():
            return peer(b, "${keys.a.public}").get("receiver_index")

        # The one handshake left that could land in the window, the 120 s rekey (§8.6), is
        # excluded by this bound: the window (< 5 s) ends before the session is 120 s old.
        assert age("session_created") < 120 - 15, "too close to the 120 s rekey"
        before = session()
        start = float(b.succeed("date +%s.%N"))
        a.succeed(
            "systemctl kill --signal=SIGSTOP kekkai-node.service"
            " && ip addr del 10.1.0.2/24 dev eth2 && ip addr add 10.1.0.3/24 dev eth2"
            " && ip route replace default via 10.1.0.1 dev eth2"
        )
        away.succeed("conntrack -F")
        a.succeed("systemctl kill --signal=SIGCONT kekkai-node.service")
        out = b.succeed(
            "until ping -c 1 -W 1 ${overlay4 "a"} >/dev/null; do :; done; date +%s.%N",
            timeout=60,
        )
        took = float(out) - start
        assert 0 < took < 5, f"traffic from B resumed after {took:.1f} s"
        assert session() == before, f"recovered by a new handshake: {before} -> {session()}"
        b.succeed(jq_peer("${keys.a.public}", f'.path == "PATH_DIRECT" and .endpoint == "{old}"'))
  '';
}
