# v1.0 acceptance (docs/milestones.md, ADR 0034, spec §4.2 to §4.4): C, listed in no
# configuration, initiates to A and pings it on the strength of its certificate; an expired
# certificate, one from another CA, one binding another key and a revoked one are refused
# without a reply; adding C to A's deny list and reloading cuts C at once. Also the status,
# log and metric additions (ADR 0019 amendment of 2026-10-29) against nisshi's and masu's
# validators.
#
# The CA and the certificates are made when the test runs, on a, by the kekkai CLI: a
# certificate made at build time would age in the store and expire under a later run. Their
# text exists only then, so each node's /etc/kekkai/node.toml is written by the test script:
# the module's file plus a `[pki]` section; a change of it is a reload as in the deployment.
# A node never sends a certificate that does not bind its own key (spec §4.2), so that message
# 1 is forged by forge-init.py. Node keys are the public test vectors of
# docs/spec/vectors/keygen.json.
{
  pkgs,
  nodeModule,
  validateLogs,
  validateMetrics,
}:
let
  inherit (pkgs) lib;
  common = import ./nat-common.nix {
    inherit pkgs nodeModule;
    lighthouseModule = null;
  };
  inherit (common) keys;
  # c uses the "kekkai 1" vector; the forger x the lighthouse vector, unknown to everyone.
  key =
    n:
    keys.${
      if n == "c" then
        "stranger"
      else if n == "x" then
        "lighthouse"
      else
        n
    };
  number = {
    a = 1;
    c = 3;
    x = 9;
  };
  underlay = n: "192.168.1.${toString number.${n}}";
  overlay4 = n: "10.77.0.${toString number.${n}}";
  overlay6 = n: "fd77::${toString number.${n}}";

  # Run on a at test time: makes the test CA, another CA and the certificates in directory $1.
  makePki = pkgs.writeShellApplication {
    name = "kekkai-test-pki";
    runtimeInputs = [
      pkgs.kekkai
      pkgs.libfaketime
      pkgs.coreutils
      pkgs.gnused
      pkgs.gnugrep
    ];
    text = ''
      mkdir -p "$1" && cd "$1"
      kekkai ca keygen > ca.seed 2>/dev/null
      kekkai ca keygen > other.seed 2>/dev/null
      kekkai ca pubkey < ca.seed > ca.pub
      kekkai ca pubkey < other.seed > other.pub
      sign() { # NAME KEY NUMBER SEED [OPTION...]
        local name=$1 key=$2 n=$3 seed=$4
        shift 4
        kekkai cert sign --key "$key" --name "$name" \
          --address "10.77.0.$n" --address "fd77::$n" "$@" < "$seed"
      }
      # Inside the 30-day warning of spec §4.2.
      sign a ${(key "a").public} 1 ca.seed --days 20 > a.cert
      sign c ${(key "c").public} 3 ca.seed > c.cert
      sign c ${(key "c").public} 3 other.seed > c-other-ca.cert
      sign c ${(key "c").public} 3 ca.seed --group revoked > c-revoked.cert
      # Expired whatever the clock, so the only certificate signed in the past.
      faketime '2020-01-01 00:00:00' kekkai cert sign --key ${(key "c").public} --name c \
        --address 10.77.0.3 --address fd77::3 --days 1 < ca.seed > c-expired.cert
      sign x ${(key "x").public} 9 ca.seed > x.cert
      show() { kekkai cert show --ca "$(cat ca.pub)" < "$1"; }
      show c-revoked.cert | sed -n 's/^deny_cert: //p' > c-revoked.deny
      show c.cert | sed -n 's/^deny_key: //p' > c-key.deny
      # Each certificate is what the test takes it for.
      for c in a c c-revoked x; do show "$c.cert" > /dev/null; done
      [ "$(show c-expired.cert 2>&1 >/dev/null)" = "kekkai: certificate expired" ]
      [ "$(show c-other-ca.cert 2>&1 >/dev/null)" = "kekkai: certificate bad_signature" ]
      grep -q '^cert:' c-revoked.deny && grep -q '^key:' c-key.deny
    '';
  };

  node = name: peers: {
    imports = [
      (common.size 512)
      (common.interfaces { eth1 = underlay name; })
      nodeModule
    ];
    nixpkgs.pkgs = pkgs;
    virtualisation.vlans = [ 1 ];
    networking.firewall.allowedUDPPorts = [ 4802 ];
    environment.systemPackages = [
      pkgs.curl
      pkgs.tcpdump
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
      peers = lib.genAttrs peers (n: {
        publicKey = (key n).public;
        addresses = [
          "${overlay4 n}/32"
          "${overlay6 n}/128"
        ];
        endpoints = [ "${underlay n}:4802" ];
      });
      metrics.listen = "127.0.0.1:9480";
    };
    # The test script writes the file, `[pki]` included, then starts the daemon.
    environment.etc."kekkai/node.toml".enable = false;
    systemd.services.kekkai-node.wantedBy = lib.mkForce [ ];
  };

  forge = pkgs.writers.writePython3 "forge-init" {
    libraries = [ pkgs.python3Packages.noiseprotocol ];
    # The script's comment lines are long; the rest is checked.
    flakeIgnore = [ "E501" ];
  } (builtins.readFile ./forge-init.py);
in
pkgs.testers.nixosTest {
  name = "kekkai-certificates";

  nodes = {
    # Lists nobody.
    a = node "a" [ ];
    # Lists a.
    c = node "c" [ "a" ];
  };

  testScript =
    { nodes, ... }:
    ''
      ${common.script}

      from datetime import datetime

      A = "${(key "a").public}"
      C = "${(key "c").public}"
      NODE = "kekkai-node.service"
      JOURNAL = f"journalctl _SYSTEMD_UNIT={NODE} -o cat"
      METRICS = "http://127.0.0.1:9480/metrics"
      BASE = {
          "a": "${nodes.a.services.kekkai-node.configFile}",
          "c": "${nodes.c.services.kekkai-node.configFile}",
      }


      def pki(name):
          """A file of the test PKI, made on a."""
          return a.succeed(f"cat /root/pki/{name}").strip()


      def configure(m, cert, ca="ca", revoked=()):
          """The node's file: the module's, plus `[pki]` with certificate `cert`, the CA `ca` and
          the deny-list entries of the files `revoked`, checked by the daemon."""
          entries = ", ".join(f'"{pki(f)}"' for f in revoked)
          m.succeed(
              f"{{ cat {BASE[m.name]}; echo; cat; }} > /etc/kekkai/node.toml <<'EOF'\n"
              "[pki]\n"
              f'ca_keys = ["{pki(ca + ".pub")}"]\n'
              f'certificate = "{pki(cert + ".cert")}"\n'
              'prefixes = ["10.77.0.0/24", "fd77::/64"]\n'
              f"revoked = [{entries}]\n"
              "EOF\n"
              "kekkai-node config check --config /etc/kekkai/node.toml"
          )


      def wait_event(m, event, count):
          m.wait_until_succeeds(
              f"[ $({JOURNAL} | grep -c '\"event\":\"{event}\"') -ge {count} ]", timeout=30
          )


      def sample(m, series):
          """The value of one series of the node's exposition, 0 when absent."""
          text = m.succeed(f"curl -sf {METRICS}")
          values = [line.split(" ")[1] for line in text.splitlines() if line.startswith(series + " ")]
          return int(values[0]) if values else 0


      def drops(m, reason):
          return sample(m, f'kekkai_dropped_packets_total{{reason="certificate_{reason}"}}')


      def wait_drop(reason, before):
          a.wait_until_succeeds(
              f"curl -sf {METRICS} | grep -F 'reason=\"certificate_{reason}\"}}' | "
              f"awk '$2 > {before} {{ moved = 1 }} END {{ exit !moved }}'",
              timeout=60,
          )


      def listed(m, key):
          return [p for p in status(m)["peers"] if p["public_key"] == key]


      def pid(m):
          return m.succeed(f"systemctl show -P MainPID {NODE}").strip()


      def reload(m, **variant):
          reloads = int(m.succeed(f"{JOURNAL} | grep -c '\"event\":\"reloaded\"' || true"))
          configure(m, **variant)
          m.succeed(f"systemctl reload {NODE}")
          wait_event(m, "reloaded", reloads + 1)


      boot(a, c)
      a.succeed("${lib.getExe makePki} /root/pki")
      # A's deny list starts with the revoked certificate; C starts with an expired one.
      configure(a, "a", revoked=["c-revoked.deny"])
      configure(c, "c-expired")
      for m in (a, c):
          m.succeed(f"systemctl start {NODE}")
          m.wait_for_unit(NODE)
      # Every datagram A sends to C's kekkai port, from the first message 1 on.
      c.succeed(
          "tcpdump -Z root -n -U -i eth1 -w /tmp/a-to-c.pcap"
          " 'src host ${underlay "a"} and dst host ${underlay "c"} and dst port 4802'"
          " >/tmp/tcpdump.log 2>&1 &"
      )
      c.wait_until_succeeds("grep -q listening /tmp/tcpdump.log")

      with subtest("status, log and metric of the own certificate"):
          own = status(a)["node"]["certificate"]
          assert own["name"] == "a" and len(own["fingerprint"]) == 44, own
          not_after = datetime.fromisoformat(own["not_after"]).timestamp()
          left = not_after - float(a.succeed("date +%s"))
          # Signed for 20 days by this run.
          assert 19 * 86400 < left <= 20 * 86400, own
          wait_event(a, "certificate-expiring", 1)
          gauge = sample(a, "kekkai_certificate_remaining_seconds")
          assert abs(gauge - left) < 120, (gauge, left)
          # C's own certificate has expired: it starts all the same and warns.
          wait_event(c, "certificate-expiring", 1)
          assert sample(c, "kekkai_certificate_remaining_seconds") < 0

      with subtest("expired, other CA, foreign key and revoked certificates get no reply"):
          for reason, variant in (
              ("expired", None),
              ("bad_signature", {"cert": "c-other-ca", "ca": "other"}),
              ("revoked", {"cert": "c-revoked"}),
          ):
              before = drops(a, reason)
              if variant:
                  reload(c, **variant)
              c.fail("ping -c 3 -W 1 ${overlay4 "a"}")
              wait_drop(reason, before)
              assert listed(a, C) == [], status(a)
          # x's certificate is answered; the same message carrying C's certificate is not.
          forge = "${forge} ${(key "x").private} ${(key "a").public}"
          c.succeed(f"{forge} {pki('x.cert')} ${underlay "a"} 4802")
          before = drops(a, "wrong_key")
          c.fail(f"{forge} {pki('c.cert')} ${underlay "a"} 4802")
          wait_drop("wrong_key", before)
          assert listed(a, C) == [], status(a)
          c.succeed("pkill -INT tcpdump")
          c.wait_until_fails("pgrep tcpdump")
          replies = c.succeed("tcpdump -n -r /tmp/a-to-c.pcap 2>/dev/null")
          assert replies.strip() == "", replies

      with subtest("C, listed nowhere, initiates to A and pings it"):
          reload(c, cert="c")
          c.wait_until_succeeds("ping -c 1 -W 1 ${overlay4 "a"}", timeout=60)
          c.succeed("ping -c 2 -W 2 ${overlay6 "a"}")
          # A routes C's certificate addresses (spec §4.4).
          a.succeed("ping -c 2 -W 2 ${overlay4 "c"}")
          p = listed(a, C)[0]
          assert p["name"] == "c" and p["path"] == "PATH_DIRECT", p
          assert p["addresses"] == ["${overlay4 "c"}/32", "${overlay6 "c"}/128"], p
          assert p["certificate"]["name"] == "c" and "groups" not in p["certificate"], p
          # A static peer has no certificate in status, even though it sent one.
          assert "certificate" not in listed(c, A)[0], status(c)
          assert status(c)["node"]["certificate"]["name"] == "c", status(c)

      with subtest("adding C to A's deny list and reloading cuts C at once"):
          before = (pid(a), drops(a, "revoked"))
          reload(a, cert="a", revoked=["c-revoked.deny", "c-key.deny"])
          assert listed(a, C) == [], status(a)
          c.fail("ping -c 3 -W 1 ${overlay4 "a"}")
          # C's next message 1 is refused as revoked.
          c.succeed("timeout 60 ping -i 1 ${overlay4 "a"} >/dev/null 2>&1 &")
          wait_drop("revoked", before[1])
          assert pid(a) == before[0], "reloaded, not restarted"

      with subtest("logs pass nisshi's schema v1, metrics pass masu's convention"):
          for m in (a, c):
              m.succeed(f"{JOURNAL} | ${validateLogs} validate --logs")
              m.succeed(f"${validateMetrics} validate --metrics {METRICS}")
    '';
}
