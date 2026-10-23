package main

import (
	"math"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scorsi/kekkai/cli/internal/genproto/kekkai/control/v1"
)

// The parity goldens of ADR 0033: each fixture is committed as its wire encoding (NAME.binpb)
// and as what formatStatus prints for it (NAME.json); the Rust CLI's test decodes the first
// and must print the second byte for byte. KEKKAI_UPDATE_GOLDENS=1 rewrites them.
const goldens = "../cli-rs/testdata/status"

// protojson adds, per binary, either one or two spaces after every key (detrand, to keep
// callers from depending on its whitespace); the goldens hold the one-space form.
var detrandSpace = regexp.MustCompile(`(?m)^( *"[a-z0-9_]+": ) `)

func ts(sec int64, nanos int32) *timestamppb.Timestamp {
	return &timestamppb.Timestamp{Seconds: sec, Nanos: nanos}
}

func dur(sec int64, nanos int32) *durationpb.Duration {
	return &durationpb.Duration{Seconds: sec, Nanos: nanos}
}

func u32(v uint32) *uint32 { return &v }

const (
	keyA = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
	keyB = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="
	keyL = "ta5DN5JdcLfn//qzn1vkBX+LgBEF698PsB10l9cpxxo="
	keyR = "HZekfj15ogjJcYSkT1dubjBB7Twk+3P6/n+fHFl14Ho="
)

func node(port uint32) *controlv1.NodeStatus {
	return &controlv1.NodeStatus{
		PublicKey:   keyA,
		Addresses:   []string{"10.0.0.1/32", "fd00::1/128"},
		Version:     "0.0.0",
		WireVersion: 1,
		Uptime:      dur(3725, 500_000_000),
		ListenPort:  port,
	}
}

var fixtures = map[string]*controlv1.GetStatusResponse{
	"empty":     {},
	"node-only": {Node: node(4802)},
	"node": {
		Node: node(4802),
		Peers: []*controlv1.PeerStatus{
			{},
			{
				PublicKey:             keyB,
				Addresses:             []string{"10.0.0.2/32"},
				Path:                  controlv1.Path_PATH_DIRECT,
				Endpoint:              "192.0.2.7:4802",
				LastHandshake:         ts(1_761_300_000, 0),
				RxBytes:               math.MaxUint64,
				TxBytes:               1 << 53,
				RxPackets:             1,
				TxPackets:             2,
				ReplayRejections:      3,
				LastDirectPathFailure: controlv1.DirectPathFailure_DIRECT_PATH_FAILURE_NO_CANDIDATES,
				AllowInbound:          []string{"tcp/22", "udp/53"},
				FirewallDrops:         12,
				Name:                  "b",
				ReceiverIndex:         u32(0),
				SessionCreated:        ts(1_761_300_000, 1),
			},
			{
				PublicKey:             keyL,
				Path:                  controlv1.Path_PATH_RELAYED,
				RelayPublicKey:        keyR,
				Endpoint:              "[2001:db8::1]:4802",
				LastHandshake:         ts(1_761_300_001, 120_000_000),
				LastDirectPathFailure: controlv1.DirectPathFailure_DIRECT_PATH_FAILURE_TIMEOUT,
				Name:                  "quote \" backslash \\ newline \n tab \t ctrl \x01\x1f del \x7f <>& é   🦀",
				ReceiverIndex:         u32(math.MaxUint32),
				SessionCreated:        ts(1_761_300_001, 120_000),
			},
			{Path: controlv1.Path_PATH_NONE, LastDirectPathFailure: controlv1.DirectPathFailure_DIRECT_PATH_FAILURE_ABANDONED},
			{LastDirectPathFailure: controlv1.DirectPathFailure_DIRECT_PATH_FAILURE_LIGHTHOUSE_UNKNOWN},
			// A value this CLI does not know (a newer daemon, 0024): printed as a number.
			{Path: controlv1.Path(99), LastDirectPathFailure: controlv1.DirectPathFailure(-1)},
		},
		Firewall: &controlv1.FirewallStatus{UdpFlows: 17, UdpFlowsMax: 1024, Evictions: 5},
		Lighthouses: []*controlv1.LighthouseStatus{
			{PublicKey: keyL, Endpoint: "lighthouse.example.org:4800", State: controlv1.SessionState_SESSION_STATE_CONNECTED, LastHandshake: ts(0, 0), LastReceived: ts(253_402_300_799, 999_999_999)},
			{PublicKey: keyL, State: controlv1.SessionState_SESSION_STATE_HANDSHAKING},
			{State: controlv1.SessionState_SESSION_STATE_DOWN},
			{State: controlv1.SessionState_SESSION_STATE_UNSPECIFIED},
		},
		Relays: []*controlv1.RelayStatus{
			{PublicKey: keyR, Endpoint: "relay.example.org:4801", State: controlv1.SessionState_SESSION_STATE_CONNECTED, LastHandshake: ts(-62_135_596_800, 0), LastReceived: ts(1_761_300_002, 5_000_000)},
		},
	},
	"node-empty-firewall": {Node: &controlv1.NodeStatus{}, Firewall: &controlv1.FirewallStatus{}},
	"lighthouse": {
		Node: &controlv1.NodeStatus{PublicKey: keyL, Version: "0.0.0", WireVersion: 1, Uptime: dur(0, 0), ListenPort: 4800},
		Registrations: []*controlv1.Registration{
			{PublicKey: keyA, Name: "a", ObservedEndpoint: "198.51.100.1:4802", LocalEndpoints: []string{"10.1.0.5:4802", "[fd12::5]:4802"}, LastSeen: dur(1, 500_000_000)},
			{PublicKey: keyB, ObservedEndpoint: "198.51.100.2:31000", LastSeen: dur(0, 1)},
			{LastSeen: dur(0, 1_000)},
			{LastSeen: dur(315_576_000_000, 0)},
			{LastSeen: dur(-1, -500_000_000)},
			{LastSeen: dur(0, -1_000_000)},
		},
	},
	"relay": {
		Node: &controlv1.NodeStatus{PublicKey: keyR, Version: "0.0.0", WireVersion: 1, Uptime: dur(86_400, 0), ListenPort: 4801},
		Senders: []*controlv1.RelaySender{
			{PublicKey: keyA, Name: "a", Connected: true, ForwardedPackets: 1000, ForwardedBytes: 1_234_567_890_123, DroppedNoRoute: 2, DroppedRateLimited: 4},
			{PublicKey: keyB, Name: "b"},
		},
	},
}

func TestStatusGoldens(t *testing.T) {
	update := os.Getenv("KEKKAI_UPDATE_GOLDENS") == "1"
	for name, reply := range fixtures {
		wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
		out, err := formatStatus(reply)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = detrandSpace.ReplaceAllString(out, "$1")
		for ext, want := range map[string]string{".binpb": string(wire), ".json": out} {
			path := filepath.Join(goldens, name+ext)
			if update {
				if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Errorf("%s differs from formatStatus; KEKKAI_UPDATE_GOLDENS=1 rewrites it", path)
			}
		}
	}
}
