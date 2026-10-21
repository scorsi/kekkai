# v0.5 acceptance (docs/milestones.md, `nat-relayed`): A and B each behind its own
# symmetric NAT (nftables `masquerade fully-random`), the lighthouse and the relay on a
# third, public network. No direct handshake can complete; both nodes report
# `path = relayed` with the relay's key, ping works, and the relay host never sees the
# plaintext of what it forwards. The relay's per-sender counters grow, and a key it does not
# list gets nothing from it. Logs and metrics pass nisshi's and masu's validators.
#
# Five VMs for a small builder: the lighthouse and the relay share the public VM (roles,
# not hosts, ADR 0005), and the stranger is a kekkai-node on router A, as in nat-direct.
{
  pkgs,
  nodeModule,
  lighthouseModule,
  relayModule,
  validateLogs,
  validateMetrics,
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
  strangerPort = 4809;
  # "kekkai pattern!!": ping fills its 64-byte payload with it after the timestamp.
  pattern = "6b656b6b6169207061747465726e2121";
in
pkgs.testers.nixosTest {
  name = "kekkai-nat-relayed";

  nodes = {
    lighthouse.imports = [
      common.lighthouse
      common.relay
    ];
    routera.imports = [
      (common.router {
        public = "192.0.2.1";
        lan = 2;
        inside = "10.1.0.1";
        masquerade = common.symmetric;
      })
      (common.kekkaiNode {
        name = "stranger";
        peers = [ "b" ];
        port = strangerPort;
        relay = true;
      })
    ];
    routerb = common.router {
      public = "192.0.2.2";
      lan = 3;
      inside = "10.2.0.1";
      masquerade = common.symmetric;
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
    ${common.script}

    RELAY = "${keys.relay.public}"
    PATTERN = "${pattern}"


    def capture(m, iface, flt, path):
        m.succeed(
            f"tcpdump -Z root -n -U -i {iface} -w {path} {flt} >/tmp/tcpdump.log 2>&1 &"
        )
        m.wait_until_succeeds("grep -q listening /tmp/tcpdump.log")


    def stop_capture(m):
        m.succeed("pkill -INT tcpdump")
        m.wait_until_fails("pgrep tcpdump")


    def holds_pattern(m, path):
        """Whether the capture file holds the pattern twice in a row, as plain bytes."""
        hex_dump = f"od -An -tx1 -v {path} | tr -d ' \\n'"
        return m.execute(f"{hex_dump} | grep -q {PATTERN}{PATTERN}")[0] == 0


    def forwarded():
        senders = status(lighthouse, RELAY_SOCKET)["senders"]
        return {s["name"]: int(s.get("forwarded_packets", "0")) for s in senders}


    boot(lighthouse, routera, routerb, a, b)
    lighthouse.wait_for_unit("kekkai-lighthouse.service")
    lighthouse.wait_for_unit("kekkai-relay.service")
    for m in (a, b, routera):
        m.wait_for_unit("kekkai-node.service")

    with subtest("config check accepts the relay module's file"):
        out = lighthouse.succeed("kekkai-relay config check --config /etc/kekkai/relay.toml 2>&1")
        assert out.strip().endswith(": ok"), out
        for m in (a, b):
            m.succeed("kekkai-node config check --config /etc/kekkai/node.toml")
            m.succeed("grep -q '^\\[\\[relays\\]\\]' /etc/kekkai/node.toml")

    with subtest("both nodes hold a session with the lighthouse and the relay"):
        for m in (a, b):
            m.wait_until_succeeds(
                "kekkai status --json | jq -e '.lighthouses[0].state == \"SESSION_STATE_CONNECTED\""
                " and .relays[0].state == \"SESSION_STATE_CONNECTED\"'",
                timeout=60,
            )
        lighthouse.wait_until_succeeds(
            f"kekkai status --json --socket {LIGHTHOUSE_SOCKET}"
            " | jq -e '[.registrations[].name] | sort == [\"a\", \"b\"]'",
            timeout=60,
        )

    with subtest("within 10 s both report path = relayed with the relay's key"):
        a.succeed("ping -c 40 -i 0.5 -W 1 ${overlay4 "b"} >/tmp/ping.log 2>&1 &")
        relayed = f'.path == "PATH_RELAYED" and .relay_public_key == "{RELAY}"'
        a.wait_until_succeeds(jq_peer("${keys.b.public}", relayed), timeout=10)
        b.wait_until_succeeds(jq_peer("${keys.a.public}", relayed), timeout=10)
        out = b.succeed("ping -c 3 -W 2 ${overlay4 "a"}")
        assert " 0% packet loss" in out, out
        for m, key in ((a, "${keys.b.public}"), (b, "${keys.a.public}")):
            p = peer(m, key)
            # §12.4: what arrived through the relay never set an endpoint.
            assert p.get("endpoint", "") == "", p
            assert p["last_direct_path_failure"] == "DIRECT_PATH_FAILURE_TIMEOUT", p

    with subtest("the relay host never sees the plaintext"):
        capture(lighthouse, "eth1", "udp port 4801", "/tmp/relay.pcap")
        capture(a, "kekkai0", "icmp", "/tmp/tunnel.pcap")
        out = a.succeed(f"ping -c 5 -i 0.3 -W 2 -s 64 -p {PATTERN} ${overlay4 "b"}")
        assert " 0% packet loss" in out, out
        stop_capture(lighthouse)
        stop_capture(a)
        relayed_packets = lighthouse.succeed("tcpdump -n -r /tmp/relay.pcap 2>/dev/null | wc -l")
        assert int(relayed_packets) >= 20, relayed_packets
        assert holds_pattern(a, "/tmp/tunnel.pcap"), "the pattern is in the tunnel"
        assert not holds_pattern(lighthouse, "/tmp/relay.pcap"), "the relay saw plaintext"

    with subtest("the relay's status shows per-sender counters growing"):
        before = forwarded()
        a.succeed("ping -c 3 -W 2 ${overlay4 "b"}")
        after = forwarded()
        assert after["a"] > before["a"] and after["b"] > before["b"], (before, after)
        senders = status(lighthouse, RELAY_SOCKET)["senders"]
        assert all(s.get("connected") for s in senders), senders
        assert all("dropped_rate_limited" not in s for s in senders), senders

    with subtest("silence: an unlisted key gets nothing from the relay"):
        capture(routera, "eth1", "udp port 4801", "/tmp/silence.pcap")
        # Past REKEY_TIMEOUT: message 1 went out at least twice.
        routera.succeed("sleep 12")
        stop_capture(routera)
        sent = routera.succeed(
            "tcpdump -n -r /tmp/silence.pcap"
            " 'src host 192.0.2.1 and src port ${toString strangerPort}"
            " and dst host ${common.lighthouseIp}' 2>/dev/null"
        )
        assert len(sent.strip().splitlines()) >= 2, sent
        replies = routera.succeed(
            "tcpdump -n -r /tmp/silence.pcap"
            " 'src host ${common.lighthouseIp} and dst host 192.0.2.1"
            " and dst port ${toString strangerPort}' 2>/dev/null"
        )
        assert replies.strip() == "", replies
        state = status(routera)["relays"][0]["state"]
        assert state != "SESSION_STATE_CONNECTED", state

    with subtest("logs pass nisshi's schema v1, metrics pass masu's convention"):
        journal = "journalctl _SYSTEMD_UNIT={}.service -o cat"
        for m, other in ((a, "b"), (b, "a")):
            m.succeed(
                journal.format("kekkai-node")
                + f" | grep -F '\"event\":\"path-change\",\"peer\":\"{other}\"'"
                + " | grep -F '\"to\":\"relayed\"'"
            )
            m.succeed(journal.format("kekkai-node") + " | grep -F relay-session-change")
            m.succeed(journal.format("kekkai-node") + " | ${validateLogs} validate --logs")
            m.succeed("${validateMetrics} validate --metrics http://127.0.0.1:9480/metrics")
            text = m.succeed("curl -sf http://127.0.0.1:9480/metrics")
            assert f'kekkai_peer_path{{peer="{other}",via="relayed"}} 1' in text, text
        lighthouse.succeed(journal.format("kekkai-relay") + " | grep -F '\"event\":\"ready\"'")
        lighthouse.succeed(journal.format("kekkai-relay") + " | ${validateLogs} validate --logs")
        # Aggregate counters only (ADR 0014, 0031): no address in its journal.
        lighthouse.fail(journal.format("kekkai-relay") + " | grep -E '10\\.[12]\\.0|192\\.0\\.2\\.[12]:'")
        metrics = "http://127.0.0.1:9482/metrics"
        lighthouse.succeed(f"${validateMetrics} validate --metrics {metrics}")
        text = lighthouse.succeed(f"curl -sf {metrics}")
        assert "kekkai_relay_sessions 2" in text, text
        assert "peer=" not in text, text
  '';
}
