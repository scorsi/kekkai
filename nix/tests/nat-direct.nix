# v0.4 acceptance (docs/milestones.md, `nat-direct`): A and B each behind its own cone NAT
# (nftables `masquerade`), the lighthouse on a third, public network. Neither node knows
# the other's endpoint from configuration; they find each other through the lighthouse and
# hold a direct path that survives the lighthouse's stop. An unlisted key gets no answer
# from the lighthouse. Logs and metrics pass nisshi's and masu's validators (ADR 0019).
{
  pkgs,
  nodeModule,
  lighthouseModule,
  validateLogs,
  validateMetrics,
}:
let
  common = import ./nat-common.nix { inherit pkgs nodeModule lighthouseModule; };
  inherit (common) keys overlay4;
in
pkgs.testers.nixosTest {
  name = "kekkai-nat-direct";

  nodes = {
    lighthouse = common.lighthouse;
    routera = common.router {
      public = "192.0.2.1";
      lan = 2;
      inside = "10.1.0.1";
    };
    routerb = common.router {
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
    };
    b = common.node {
      name = "b";
      vlans = [ 3 ];
      ifs.eth1 = "10.2.0.2";
      gateway = "10.2.0.1";
      peers = [ "a" ];
    };
    # On the public network, configured with the lighthouse, but not listed by it.
    stranger = common.node {
      name = "stranger";
      vlans = [ 1 ];
      ifs.eth1 = "192.0.2.20";
      gateway = "192.0.2.1";
      peers = [ "b" ];
    };
  };

  testScript = ''
    ${common.script}

    start_all()
    lighthouse.wait_for_unit("kekkai-lighthouse.service")
    for m in (a, b, stranger):
        m.wait_for_unit("kekkai-node.service")

    with subtest("config check accepts the lighthouse module's file"):
        out = lighthouse.succeed(
            "kekkai-lighthouse config check --config /etc/kekkai/lighthouse.toml 2>&1"
        )
        assert out.strip().endswith(": ok"), out
        for m in (a, b):
            m.succeed("kekkai-node config check --config /etc/kekkai/node.toml")
            m.fail("grep -q endpoints /etc/kekkai/node.toml")

    with subtest("both nodes hold a session with the lighthouse and are registered"):
        for m in (a, b):
            m.wait_until_succeeds(
                "kekkai status --json | jq -e '.lighthouses[0].state == \"SESSION_STATE_CONNECTED\"'",
                timeout=60,
            )
        lighthouse.wait_until_succeeds(
            f"kekkai status --json --socket {LIGHTHOUSE_SOCKET}"
            " | jq -e '[.registrations[].name] | sort == [\"a\", \"b\"]'",
            timeout=60,
        )
        regs = status(lighthouse, LIGHTHOUSE_SOCKET)["registrations"]
        observed = {r["name"]: r["observed_endpoint"] for r in regs}
        assert observed["a"].startswith("192.0.2.1:"), regs
        assert observed["b"].startswith("192.0.2.2:"), regs

    with subtest("A and B find each other: direct path to the other's NAT address"):
        a.wait_until_succeeds("ping -c 1 -W 1 ${overlay4 "b"}", timeout=60)
        out = b.succeed("ping -c 3 -W 2 ${overlay4 "a"}")
        assert " 0% packet loss" in out, out
        for m, key, nat in (
            (a, "${keys.b.public}", "192.0.2.2:"),
            (b, "${keys.a.public}", "192.0.2.1:"),
        ):
            p = peer(m, key)
            assert p["path"] == "PATH_DIRECT", p
            assert p["endpoint"].startswith(nat), p

    with subtest("silence: an unlisted key gets nothing from the lighthouse"):
        stranger.succeed(
            "tcpdump -Z root -n -U -i eth1 -w /tmp/silence.pcap udp port 4800"
            " >/tmp/tcpdump.log 2>&1 &"
        )
        stranger.wait_until_succeeds("grep -q listening /tmp/tcpdump.log")
        # Past REKEY_TIMEOUT: message 1 went out at least twice.
        stranger.succeed("sleep 12")
        stranger.succeed("pkill -INT tcpdump")
        stranger.wait_until_fails("pgrep tcpdump")
        sent = stranger.succeed(
            "tcpdump -n -r /tmp/silence.pcap"
            " 'src host 192.0.2.20 and dst host ${common.lighthouseIp}' 2>/dev/null"
        )
        assert len(sent.strip().splitlines()) >= 2, sent
        replies = stranger.succeed(
            "tcpdump -n -r /tmp/silence.pcap"
            " 'src host ${common.lighthouseIp} and dst host 192.0.2.20' 2>/dev/null"
        )
        assert replies.strip() == "", replies
        state = status(stranger)["lighthouses"][0]["state"]
        assert state != "SESSION_STATE_CONNECTED", state

    with subtest("logs pass nisshi's schema v1, metrics pass masu's convention"):
        journal = "journalctl _SYSTEMD_UNIT={}.service -o cat"
        for m, other in ((a, "b"), (b, "a")):
            m.wait_until_succeeds(
                journal.format("kekkai-node")
                + f" | grep -F '\"event\":\"handshake-completed\",\"peer\":\"{other}\"'"
            )
            m.succeed(journal.format("kekkai-node") + " | ${validateLogs} validate --logs")
            m.succeed("${validateMetrics} validate --metrics http://127.0.0.1:9480/metrics")
        lighthouse.succeed(
            journal.format("kekkai-lighthouse") + " | grep -F '\"event\":\"ready\"'"
        )
        lighthouse.succeed(
            journal.format("kekkai-lighthouse") + " | ${validateLogs} validate --logs"
        )
        # Aggregate counters only (ADR 0012): no node name, no address in its journal.
        lighthouse.fail(journal.format("kekkai-lighthouse") + " | grep -E '10\\.[12]\\.0|192\\.0\\.2\\.[12]:'")
        metrics = "http://127.0.0.1:9481/metrics"
        lighthouse.succeed(f"${validateMetrics} validate --metrics {metrics}")
        text = lighthouse.succeed(f"curl -sf {metrics}")
        assert "kekkai_lighthouse_registrations 2" in text, text
        assert "peer=" not in text, text

    with subtest("stopping the lighthouse does not break the A-B session"):
        lighthouse.systemctl("stop kekkai-lighthouse.service")
        # The lighthouse session ends at REJECT_AFTER_TIME (180 s) at the latest.
        a.wait_until_succeeds(
            "kekkai status --json | jq -e '.lighthouses[0].state != \"SESSION_STATE_CONNECTED\"'",
            timeout=240,
        )
        for m, target in ((a, "${overlay4 "b"}"), (b, "${overlay4 "a"}")):
            out = m.succeed(f"ping -c 3 -W 2 {target}")
            assert " 0% packet loss" in out, out
        assert peer(a, "${keys.b.public}")["path"] == "PATH_DIRECT"
  '';
}
