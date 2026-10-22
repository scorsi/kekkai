# v0.6 acceptance (docs/milestones.md, ADR 0026, spec §4.1): a `switch` that only changes the
# peer list reloads kekkai-node (SIGHUP) instead of restarting it. Adding a peer makes it
# reachable, removing one makes its handshakes refused, an unchanged peer keeps its session
# (same receiver index), an invalid file changes nothing, and a restart-only section
# restarts. The lighthouse and relay on c reload their peer lists the same way. Each
# configuration change is a specialisation of the same system, switched with
# `switch-to-configuration test`, so the module's reload and restart triggers are what is
# tested. Keys are the public test vectors of docs/spec/vectors/keygen.json.
{
  pkgs,
  nodeModule,
  lighthouseModule,
  relayModule,
}:
let
  inherit (pkgs) lib;
  common = import ./nat-common.nix {
    inherit
      pkgs
      nodeModule
      lighthouseModule
      relayModule
      ;
  };
  inherit (common) keys;
  # c uses the "kekkai 1" vector (the other tests' stranger).
  key = n: keys.${if n == "c" then "stranger" else n};
  number = {
    a = 1;
    b = 2;
    c = 3;
  };
  underlay = n: "192.168.1.${toString number.${n}}";
  overlay4 = n: "10.77.0.${toString number.${n}}";
  overlay6 = n: "fd77::${toString number.${n}}";
  peer = n: {
    publicKey = (key n).public;
    addresses = [
      "${overlay4 n}/32"
      "${overlay6 n}/128"
    ];
    endpoints = [ "${underlay n}:4802" ];
  };
  peers = lib.genAttrs;
  named =
    names:
    peers names (n: {
      publicKey = (key n).public;
    });
  node = name: listed: {
    imports = [
      (common.size 512)
      (common.interfaces { eth1 = underlay name; })
      nodeModule
    ];
    nixpkgs.pkgs = pkgs;
    virtualisation.vlans = [ 1 ];
    networking.firewall.allowedUDPPorts = [
      4802
      4803
    ];
    environment.systemPackages = [
      pkgs.curl
      pkgs.jq
    ];
    # Stands in for the sops-nix secret (0017).
    environment.etc."kekkai/key" = {
      text = (key name).private + "\n";
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
      peers = peers listed peer;
      metrics.listen = "127.0.0.1:9480";
    };
  };
in
pkgs.testers.nixosTest {
  name = "kekkai-reload";

  nodes = {
    a = {
      imports = [ (node "a" [ "b" ]) ];
      specialisation = {
        added.configuration.services.kekkai-node.peers = lib.mkForce (peers [ "b" "c" ] peer);
        # The daemon refuses a /24 (spec §11), the module's types do not.
        invalid.configuration.services.kekkai-node.peers = lib.mkForce (
          peers [ "b" "c" ] peer
          // {
            bad = {
              publicKey = keys.relay.public;
              addresses = [ "10.77.0.9/24" ];
            };
          }
        );
        removed.configuration.services.kekkai-node.peers = lib.mkForce (peers [ "c" ] peer);
        # A restart-only section (spec §4.1).
        port.configuration.services.kekkai-node.listenPort = 4803;
      };
    };
    b = node "b" [
      "a"
      "c"
    ];
    c = {
      imports = [
        (node "c" [
          "a"
          "b"
        ])
        lighthouseModule
        relayModule
      ];
      environment.etc."kekkai/lighthouse-key" = {
        text = keys.lighthouse.private + "\n";
        mode = "0400";
        user = "kekkai-lighthouse";
        group = "kekkai-lighthouse";
      };
      environment.etc."kekkai/relay-key" = {
        text = keys.relay.private + "\n";
        mode = "0400";
        user = "kekkai-relay";
        group = "kekkai-relay";
      };
      services.kekkai-lighthouse = {
        enable = true;
        privateKeyFile = "/etc/kekkai/lighthouse-key";
        peers = named [ "a" ];
      };
      services.kekkai-relay = {
        enable = true;
        privateKeyFile = "/etc/kekkai/relay-key";
        peers = named [ "a" ];
      };
      specialisation.added.configuration = {
        services.kekkai-lighthouse.peers = lib.mkForce (named [
          "a"
          "b"
        ]);
        services.kekkai-relay.peers = lib.mkForce (named [
          "a"
          "b"
        ]);
      };
    };
  };

  testScript =
    { nodes, ... }:
    ''
      ${common.script}

      import time
      from datetime import datetime

      B = "${keys.b.public}"
      C = "${keys.stranger.public}"
      # Spec §3: the initiator rekeys a session this old (§8.6), the responder later. A
      # receiver index is compared across at most WINDOW seconds, on a session young enough
      # that no rekey can replace it meanwhile (spec §4.1: a later rekey is not the reload).
      REKEY_AFTER_TIME = 120
      WINDOW = 60
      SYSTEM = {
          "a": "${nodes.a.system.build.toplevel}",
          "c": "${nodes.c.system.build.toplevel}",
      }


      def switch(m, spec):
          """Switches to a specialisation; the units s-t-c reloaded, restarted or stopped."""
          out = m.succeed(
              f"{SYSTEM[m.name]}/specialisation/{spec}/bin/switch-to-configuration test 2>&1"
          )
          acted = {}
          for line in out.splitlines():
              for verb in ("reloading", "restarting", "stopping"):
                  if line.startswith(f"{verb} the following units: "):
                      acted[verb] = line.split(": ", 1)[1].split(", ")
          return acted


      def reloaded_only(acted, unit):
          assert unit in acted.get("reloading", []), acted
          assert unit not in acted.get("restarting", []) + acted.get("stopping", []), acted


      def process(m, unit):
          """MainPID and the automatic restart counter."""
          return m.succeed(f"systemctl show -P MainPID,NRestarts {unit}").split()


      def wait_event(m, unit, event, count):
          journal = f"journalctl _SYSTEMD_UNIT={unit} -o cat"
          m.wait_until_succeeds(
              f"[ $({journal} | grep -c '\"event\":\"{event}\"') -ge {count} ]", timeout=30
          )


      def fresh_indices(m, addresses):
          """The receiver index of each key of `addresses` (key: overlay address) and the end
          of the comparison window, once every session is younger than REKEY_AFTER_TIME -
          WINDOW; pings the addresses until rekeys make them so."""
          for _ in range(40):
              for ip in addresses.values():
                  m.succeed(f"ping -c 3 -i 1 -W 2 {ip} >/dev/null")
              now = float(m.succeed("date +%s.%N"))
              peers = {k: peer(m, k) for k in addresses}
              made = {
                  k: datetime.fromisoformat(p["last_handshake"].replace("Z", "+00:00"))
                  for k, p in peers.items()
              }
              if all(now - t.timestamp() < REKEY_AFTER_TIME - WINDOW for t in made.values()):
                  indices = {k: p["receiver_index"] for k, p in peers.items()}
                  return indices, time.monotonic() + WINDOW
          raise Exception(f"no fresh sessions: {status(m)}")


      def same_indices(m, kept):
          indices, deadline = kept
          assert time.monotonic() < deadline, f"over {WINDOW} s: a rekey may have run"
          now = {k: peer(m, k)["receiver_index"] for k in indices}
          assert now == indices, (indices, status(m))


      def routes(m):
          return (
              m.succeed("ip route show dev kekkai0"),
              m.succeed("ip -6 route show dev kekkai0"),
          )


      def listed(m, key):
          return [p for p in status(m)["peers"] if p["public_key"] == key]


      def rejected(m):
          text = m.succeed("curl -sf http://127.0.0.1:9480/metrics")
          prefix = 'kekkai_dropped_packets_total{reason="identity_rejected"} '
          return sum(int(x[len(prefix):]) for x in text.splitlines() if x.startswith(prefix))


      NODE = "kekkai-node.service"
      boot(a, b, c)
      for m in (a, b, c):
          m.wait_for_unit(NODE)
      c.wait_for_unit("kekkai-lighthouse.service")
      c.wait_for_unit("kekkai-relay.service")

      with subtest("before: a and b talk, a refuses c"):
          a.wait_until_succeeds("ping -c 1 -W 1 ${overlay4 "b"}", timeout=60)
          c.fail("ping -c 3 -W 1 ${overlay4 "a"}")
          assert listed(a, C) == [], status(a)

      with subtest("adding a peer reloads: it becomes reachable, b keeps its session"):
          before = process(a, NODE)
          kept = fresh_indices(a, {B: "${overlay4 "b"}"})
          reloaded_only(switch(a, "added"), NODE)
          wait_event(a, NODE, "reloaded", 1)
          same_indices(a, kept)
          a.succeed("ping -c 2 -W 2 ${overlay4 "b"}")
          same_indices(a, kept)
          c.wait_until_succeeds("ping -c 1 -W 1 ${overlay4 "a"}", timeout=60)
          a.succeed("ping -c 2 -W 2 ${overlay6 "c"}")
          assert "${overlay4 "c"}" in a.succeed("ip route show dev kekkai0")
          assert "${overlay6 "c"}" in a.succeed("ip -6 route show dev kekkai0")
          assert process(a, NODE) == before, (before, process(a, NODE))

      with subtest("an invalid file is refused and changes nothing"):
          before = process(a, NODE)
          kept = fresh_indices(a, {B: "${overlay4 "b"}", C: "${overlay4 "c"}"})
          installed = routes(a)
          reloaded_only(switch(a, "invalid"), NODE)
          wait_event(a, NODE, "reload-failed", 1)
          assert {p["name"] for p in status(a)["peers"]} == {"b", "c"}, status(a)
          same_indices(a, kept)
          assert routes(a) == installed, (installed, routes(a))
          a.succeed("ping -c 2 -W 2 ${overlay4 "c"}")
          assert process(a, NODE) == before

      with subtest("removing a peer reloads: its handshakes are refused, c keeps its session"):
          before = process(a, NODE)
          kept = fresh_indices(a, {C: "${overlay4 "c"}"})
          refused = rejected(a)
          reloaded_only(switch(a, "removed"), NODE)
          wait_event(a, NODE, "reloaded", 2)
          assert listed(a, B) == [], status(a)
          assert "${overlay4 "b"}" not in a.succeed("ip route show dev kekkai0")
          assert "${overlay6 "b"}" not in a.succeed("ip -6 route show dev kekkai0")
          same_indices(a, kept)
          # b still holds its session: past the 15 s "new handshake" timer it initiates
          # again, and a drops its message 1 (spec §7.6 identity).
          b.succeed("timeout 60 ping -i 1 ${overlay4 "a"} >/dev/null 2>&1 &")
          a.wait_until_succeeds(f"[ $(curl -sf http://127.0.0.1:9480/metrics | grep -F 'reason=\"identity_rejected\"' | cut -d' ' -f2) -gt {refused} ]", timeout=60)
          b.fail("ping -c 3 -W 1 ${overlay4 "a"}")
          assert process(a, NODE) == before

      with subtest("lighthouse and relay reload their peer lists"):
          units = ("kekkai-lighthouse.service", "kekkai-relay.service")
          before = [process(c, u) for u in units]
          node_before = process(c, NODE)
          acted = switch(c, "added")
          for u in units:
              reloaded_only(acted, u)
              wait_event(c, u, "reloaded", 1)
              line = c.succeed(f"journalctl _SYSTEMD_UNIT={u} -o cat | grep -F '\"event\":\"reloaded\"'")
              event = json.loads(line.splitlines()[-1])
              assert (event["peers"], event["added"], event["removed"]) == (2, 1, 0), line
          assert [process(c, u) for u in units] == before
          assert process(c, NODE) == node_before, "c's node file did not change"

      with subtest("a restart-only section restarts the node"):
          before = process(a, NODE)
          switch(a, "port")
          a.wait_for_unit(NODE)
          assert process(a, NODE)[0] != before[0], (before, process(a, NODE))
          a.wait_until_succeeds("ss -uln | grep -q ':4803 '")
    '';
}
