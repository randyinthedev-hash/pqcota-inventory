// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package inventory_test

import (
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

const (
	cl = discoveryv1.EdgeRole_EDGE_ROLE_CLIENT
	sv = discoveryv1.EdgeRole_EDGE_ROLE_SERVER
	un = discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED
)

func tEdge(src, dst string, port uint32, role discoveryv1.EdgeRole, group, app string, count uint64) *discoveryv1.ObservedEdge {
	return &discoveryv1.ObservedEdge{SrcNodeId: src, DstAddr: dst, Port: port, Role: role, NegotiatedGroup: group,
		AppKey: app, AppKeyKind: "exe-path", Protocol: discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS, ObservedCount: count}
}

func lib(name, version string, keys ...string) *discoveryv1.Finding {
	return &discoveryv1.Finding{AppKeys: keys, RuntimeAxes: &discoveryv1.Finding_Openssl{Openssl: &discoveryv1.OpensslAxes{Lib: name, Version: version}}}
}

func ep(node, ip string) *inventoryv1.MachineEndpoint {
	return &inventoryv1.MachineEndpoint{NodeId: node, Name: node, Ip: ip, Port: 22}
}

var (
	t1 = time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)
	t2 = time.Date(2026, 11, 23, 6, 30, 5, 0, time.UTC)
	t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
)

// scenario — 완료 기준 T1~T8을 한 그림에 담는다.
func scenario() inventory.TopologyInput {
	return inventory.TopologyInput{
		Snapshots: []*history.Snapshot{
			{ID: "s-web-01-aaaaaaaaaaaa", NodeID: "web-01", Edges: []*discoveryv1.ObservedEdge{
				tEdge("web-01", "10.0.1.20:443", 443, cl, "X25519MLKEM768", "/usr/bin/openssl", 3),   // T2 클라이언트 쪽
				tEdge("web-01", "10.0.1.40:8443", 8443, cl, "X25519MLKEM768", "/usr/bin/openssl", 2), // T1 한쪽만(web-03은 스냅샷 없음)
				tEdge("web-01", "10.0.1.50:5432", 5432, cl, "secp256r1", "/usr/bin/psql", 1),         // T4 중복 IP
				tEdge("web-01", "10.0.1.30:5432", 5432, cl, "secp256r1", "/usr/bin/psql", 4),         // T5 미등록
				tEdge("web-01", "10.0.1.20", 0, un, "", "/usr/sbin/sshd", 1),                         // T3(가) 지금 꼴의 미확인
			}, Findings: []*discoveryv1.Finding{
				lib("libssl.so.3", "", "/usr/bin/openssl"),
				lib("libcrypto.so.3", "3.5.8", "/usr/bin/openssl"),
				lib("libnginx-only.so", "", "/usr/sbin/nginx"), // T7 다른 노드의 앱 키 — web-01에는 그 앱이 없다
				lib("libnokey.so", ""),                         // T7 빈 앱 키
			}},
			{ID: "s-web-02-bbbbbbbbbbbb", NodeID: "web-02", Edges: []*discoveryv1.ObservedEdge{
				tEdge("web-02", "10.0.1.10", 443, sv, "X25519MLKEM768", "/usr/sbin/nginx", 3), // T2 서버 쪽
			}, Findings: []*discoveryv1.Finding{lib("libssl.so.3", "", "/usr/sbin/nginx")}},
			{ID: "s-old-01-cccccccccccc", NodeID: "old-01", Edges: []*discoveryv1.ObservedEdge{
				{SrcNodeId: "old-01", DstAddr: "10.0.1.99:22", Port: 22}, // T3(나) 이전 판의 역할 없는 기록
			}},
			{ID: "s-v6-cli-dddddddddddd", NodeID: "v6-cli", Edges: []*discoveryv1.ObservedEdge{
				tEdge("v6-cli", "fd00::20:8443", 8443, cl, "", "", 1),   // T6 괄호 없는 IPv6 CLIENT
				tEdge("v6-cli", "::ffff:10.0.1.10", 443, sv, "", "", 1), // T6 ::ffff: 매핑
			}},
		},
		Times: map[string]inventory.NodeTime{
			"web-01": {At: t1, Loaded: true},
			"web-02": {At: t2, Loaded: true},
			"old-01": {At: t0}, // 관측 기록이 없는 옛 이력
			"v6-cli": {At: t2, Loaded: true},
		},
		Endpoints: []*inventoryv1.MachineEndpoint{
			ep("web-01", "10.0.1.10"), ep("web-02", "10.0.1.20"), ep("web-03", "10.0.1.40"),
			ep("db-a", "10.0.1.50"), ep("db-b", "10.0.1.50"), ep("old-target", "10.0.1.99"), ep("v6-srv", "fd00::20"),
		},
	}
}

// edges — DOT의 선 줄을 「from -> to」별로 모은다.
func edgeLines(dot string) []string {
	var out []string
	for _, l := range strings.Split(dot, "\n") {
		if strings.Contains(l, " -> ") {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

func linesFrom(dot, from, to string) []string {
	var out []string
	for _, l := range edgeLines(dot) {
		if strings.HasPrefix(l, `"`+from+`" -> "`+to+`"`) {
			out = append(out, l)
		}
	}
	return out
}

func has(t *testing.T, s, sub, what string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("%s: missing %q in\n%s", what, sub, s)
	}
}

// T2(핵심): 양쪽에서 관측한 연결은 선 둘. 선마다 관측 노드·역할·그 기록의 횟수. 횟수를 더하지 않는다. 앱은 각자의 것.
func TestTopologyBothSidesAreTwoLines(t *testing.T) {
	dot, _ := inventory.RenderTopology(scenario())
	cli := linesFrom(dot, "app|6:web-01|/usr/bin/openssl", "node|web-02")
	srv := linesFrom(dot, "node|web-01", "app|6:web-02|/usr/sbin/nginx")
	if len(cli) != 1 || len(srv) != 1 {
		t.Fatalf("want exactly one client-side and one server-side line, got %d and %d:\n%s", len(cli), len(srv), strings.Join(edgeLines(dot), "\n"))
	}
	has(t, cli[0], `tls :443 · X25519MLKEM768 · ×3\nseen by web-01 as client`, "client-side record")
	has(t, srv[0], `tls :443 · X25519MLKEM768 · ×3\nseen by web-02 as server`, "server-side record")
	for _, l := range append(cli, srv...) {
		if strings.Contains(l, "dir=none") || strings.Contains(l, "dashed") {
			t.Errorf("a confirmed role was drawn as unconfirmed: %s", l)
		}
	}
	// 둘 사이의 :443 선은 이 둘뿐이고, 횟수는 합쳐지지 않는다.
	n := 0
	for _, l := range edgeLines(dot) {
		ends := strings.SplitN(l, " [", 2)[0]
		if strings.Contains(ends, "web-01") && strings.Contains(ends, "web-02") && strings.Contains(l, "tls :443") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("web-01 ↔ web-02 :443 lines: %d, want 2", n)
	}
	if strings.Contains(dot, "×6") {
		t.Error("the counts of the two records were added up (×6)")
	}
	has(t, dot, `"app|6:web-01|/usr/bin/openssl" [label="/usr/bin/openssl\n(exe-path)", shape=component]`, "web-01's own app")
	has(t, dot, `"app|6:web-02|/usr/sbin/nginx" [label="/usr/sbin/nginx\n(exe-path)", shape=component]`, "web-02's own app")
}

// T1: 한쪽만 관측. 상대는 스냅샷이 없는 등록 노드.
func TestTopologyOneSide(t *testing.T) {
	dot, _ := inventory.RenderTopology(scenario())
	l := linesFrom(dot, "app|6:web-01|/usr/bin/openssl", "node|web-03")
	if len(l) != 1 {
		t.Fatalf("lines to web-03: %v", l)
	}
	has(t, l[0], `×2\nseen by web-01 as client`, "one-side record")
	has(t, dot, `"node|web-03" [label="web-03\nregistered, no snapshot"`, "registered node without a snapshot")
}

// T3: 역할 미확인 — 지금 꼴과 이전 판의 역할 없는 기록. 둘 다 화살표 없는 점선이고, 옛 기록도 등록 노드로 이어진다.
func TestTopologyRoleNotConfirmed(t *testing.T) {
	dot, _ := inventory.RenderTopology(scenario())
	for name, l := range map[string][]string{
		"current form (IP only)":          linesFrom(dot, "app|6:web-01|/usr/sbin/sshd", "node|web-02"),
		"older record (ip:port, no role)": linesFrom(dot, "node|old-01", "node|old-target"),
	} {
		if len(l) != 1 {
			t.Fatalf("%s: %v", name, l)
		}
		has(t, l[0], "style=dashed, dir=none", name)
		has(t, l[0], "role not confirmed", name)
	}
	if strings.Contains(dot, "addr|10.0.1.99") {
		t.Error("the older record's registered peer was drawn as an address")
	}
}

// T4·T5: 같은 IP를 쓰는 등록 노드 둘, 미등록 IP — 주소 상자와 그 이유.
func TestTopologySharedAndUnregisteredIP(t *testing.T) {
	dot, sum := inventory.RenderTopology(scenario())
	if len(linesFrom(dot, "app|6:web-01|/usr/bin/psql", "addr|10.0.1.50")) != 1 {
		t.Error("the shared IP did not end at an address box")
	}
	has(t, dot, `"addr|10.0.1.50" [label="10.0.1.50\nIP shared by 2 registered nodes", shape=note]`, "shared IP")
	for _, n := range []string{"node|db-a", "node|db-b"} {
		if strings.Contains(dot, `"`+n+`"`) {
			t.Errorf("a line was tied to %s although its IP is shared", n)
		}
	}
	if len(linesFrom(dot, "app|6:web-01|/usr/bin/psql", "addr|10.0.1.30")) != 1 {
		t.Error("the unregistered IP did not end at an address box")
	}
	has(t, dot, `"addr|10.0.1.30" [label="10.0.1.30\nunregistered", shape=note]`, "unregistered IP")
	if sum.Addresses != 2 {
		t.Errorf("address boxes %d, want 2", sum.Addresses)
	}
}

// T6: 괄호 없는 IPv6 CLIENT 주소("fd00::20:8443")는 포트를 떼어 읽는다. ::ffff: 매핑은 IPv4로.
func TestTopologyIPv6(t *testing.T) {
	dot, _ := inventory.RenderTopology(scenario())
	if len(linesFrom(dot, "node|v6-cli", "node|v6-srv")) != 1 {
		t.Errorf("the IPv6 client record did not reach v6-srv:\n%s", strings.Join(edgeLines(dot), "\n"))
	}
	if len(linesFrom(dot, "node|web-01", "node|v6-cli")) != 1 {
		t.Error("the ::ffff: peer was not tied to web-01")
	}
}

// T7: 앱과 라이브러리는 같은 노드·같은 스냅샷에서 비어 있지 않은 앱 키가 같을 때만. 범례 문구.
func TestTopologyAppLibraries(t *testing.T) {
	dot, _ := inventory.RenderTopology(scenario())
	for _, l := range []string{"libssl.so.3", "libcrypto.so.3 3.5.8"} {
		got := linesFrom(dot, "app|6:web-01|/usr/bin/openssl", "lib|6:web-01|"+l)
		if len(got) != 1 || !strings.Contains(got[0], "style=dotted") {
			t.Errorf("%s: %v", l, got)
		}
	}
	if len(linesFrom(dot, "app|6:web-02|/usr/sbin/nginx", "lib|6:web-02|libssl.so.3")) != 1 {
		t.Error("web-02's library was not tied to its app")
	}
	for _, l := range []string{"libnginx-only.so", "libnokey.so"} {
		if strings.Contains(dot, l) {
			t.Errorf("%s was drawn (different node's key or empty key)", l)
		}
	}
	has(t, dot, "library observed with the same app key (not evidence that the connection used it)", "legend")
}

// T8: 노드마다 마지막 적재 시각(UTC). 관측 기록이 없는 옛 이력은 스냅샷 생성 시각. 「관측」으로 시각을 적지 않는다.
func TestTopologyLoadTimes(t *testing.T) {
	dot, _ := inventory.RenderTopology(scenario())
	has(t, dot, `last loaded 2026-11-23T06:00:00Z\nsnapshot s-web-01-aaa`, "web-01 load time")
	has(t, dot, `last loaded 2026-11-23T06:30:05Z\nsnapshot s-web-02-bbb`, "web-02 load time")
	has(t, dot, `snapshot created 2026-10-01T00:00:00Z`, "older history")
	has(t, dot, "load times differ per node", "top label")
	if regexp.MustCompile(`observed 20\d\d-`).MatchString(dot) {
		t.Error("a time was labelled as an observation time")
	}
}

// T9: 같은 입력이면 같은 바이트. 노드·엣지·자산·엔드포인트 순서를 섞어도 같다.
func TestTopologyDeterministic(t *testing.T) {
	want, _ := inventory.RenderTopology(scenario())
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 20; i++ {
		in := scenario()
		r.Shuffle(len(in.Snapshots), func(a, b int) { in.Snapshots[a], in.Snapshots[b] = in.Snapshots[b], in.Snapshots[a] })
		r.Shuffle(len(in.Endpoints), func(a, b int) { in.Endpoints[a], in.Endpoints[b] = in.Endpoints[b], in.Endpoints[a] })
		for _, s := range in.Snapshots {
			r.Shuffle(len(s.Edges), func(a, b int) { s.Edges[a], s.Edges[b] = s.Edges[b], s.Edges[a] })
			r.Shuffle(len(s.Findings), func(a, b int) { s.Findings[a], s.Findings[b] = s.Findings[b], s.Findings[a] })
		}
		if got, _ := inventory.RenderTopology(in); got != want {
			t.Fatalf("output changed with input order (round %d)", i)
		}
	}
}

// 저장소에서 읽기: 노드마다 Latest, 시각은 마지막 적재 시각, 등록 목록.
func TestLoadTopologyFromStores(t *testing.T) {
	store := history.NewMemStore()
	meta := inventory.NewMemMetaStore()
	for _, s := range scenario().Snapshots[:2] {
		cp := *s
		cp.RulesetVersion = "r"
		if err := store.Append(&cp); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range scenario().Endpoints {
		if err := meta.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	in, err := inventory.LoadTopology(store, meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Snapshots) != 2 || len(in.Endpoints) != 7 || !in.Times["web-01"].Loaded || in.Times["web-01"].At.IsZero() {
		t.Fatalf("loaded %d snapshots, %d endpoints, times %+v", len(in.Snapshots), len(in.Endpoints), in.Times)
	}
	if in.Endpoints[0].GetNodeId() != "db-a" {
		t.Errorf("endpoints are not in node order: %v", in.Endpoints[0])
	}
	dot, sum := inventory.RenderTopology(in)
	if sum.Nodes != 3 || sum.Edges != 6 { // web-01·web-02 + 스냅샷 없는 web-03
		t.Errorf("summary %+v", sum)
	}
	has(t, dot, "last loaded ", "load time from observation stats")
}

// 회귀(검토 1): 노드 ID나 앱 키에 「|」가 있어도 두 노드의 앱이 합쳐지지 않는다. (노드 "a|b", 앱 "c")와 (노드 "a", 앱 "b|c")는
// 각자의 클러스터에 각자의 앱으로 있고, 선도 각자의 것이다. 라이브러리도 같다.
func TestTopologyIDsKeepBoundaries(t *testing.T) {
	in := inventory.TopologyInput{Snapshots: []*history.Snapshot{
		{ID: "s1", NodeID: "a|b", Edges: []*discoveryv1.ObservedEdge{tEdge("a|b", "192.0.2.1:443", 443, cl, "", "c", 1)},
			Findings: []*discoveryv1.Finding{lib("libx.so", "", "c")}},
		{ID: "s2", NodeID: "a", Edges: []*discoveryv1.ObservedEdge{tEdge("a", "192.0.2.2:443", 443, cl, "", "b|c", 1)},
			Findings: []*discoveryv1.Finding{lib("libx.so", "", "b|c")}},
	}}
	dot, _ := inventory.RenderTopology(in)
	appAB, appA := "app|3:a|b|c", "app|1:a|b|c"
	for _, c := range []struct{ app, lib, addr, cluster string }{
		{appAB, "lib|3:a|b|libx.so", "addr|192.0.2.1", `label="a|b`},
		{appA, "lib|1:a|libx.so", "addr|192.0.2.2", `label="a\n`},
	} {
		if len(linesFrom(dot, c.app, c.addr)) != 1 || len(linesFrom(dot, c.app, c.lib)) != 1 {
			t.Errorf("%s: its line or library is missing:\n%s", c.app, dot)
		}
		// 앱 선언은 그 노드의 클러스터 안에만 있다.
		start := strings.Index(dot, c.cluster)
		end := strings.Index(dot[start:], "  }\n")
		if start < 0 || end < 0 || !strings.Contains(dot[start:start+end], `"`+c.app+`" [label=`) {
			t.Errorf("%s is not declared inside its own cluster", c.app)
		}
	}
	if strings.Count(dot, `"`+appAB+`" [label=`)+strings.Count(dot, `"`+appA+`" [label=`) != 2 {
		t.Error("the two apps were not declared once each")
	}
	if len(linesFrom(dot, appAB, "addr|192.0.2.2")) != 0 || len(linesFrom(dot, appA, "addr|192.0.2.1")) != 0 {
		t.Error("one node's record was attached to the other node's app")
	}
}

// 회귀(검토 2): 같은 앱 키의 기록 둘이 종류를 빈 값과 systemd-unit으로 달리 보고해도, 비어 있지 않은 값을 모아 정렬해
// 적는다. 기록 순서를 뒤집어도 DOT 바이트가 같다.
func TestTopologyAppKindsAreStable(t *testing.T) {
	mk := func(kinds ...string) inventory.TopologyInput {
		var edges []*discoveryv1.ObservedEdge
		for i, k := range kinds {
			e := tEdge("n1", "192.0.2."+strconv.Itoa(i+1)+":443", 443, cl, "", "sshd.service", 1)
			e.AppKeyKind = k
			edges = append(edges, e)
		}
		return inventory.TopologyInput{Snapshots: []*history.Snapshot{{ID: "s", NodeID: "n1", Edges: edges}}}
	}
	a, _ := inventory.RenderTopology(mk("", "systemd-unit"))
	b, _ := inventory.RenderTopology(mk("systemd-unit", ""))
	if a != b {
		t.Fatal("the app label depends on the order of the records")
	}
	has(t, a, `[label="sshd.service\n(systemd-unit)", shape=component]`, "kind kept")
	c, _ := inventory.RenderTopology(mk("systemd-unit", "exe-path"))
	d, _ := inventory.RenderTopology(mk("exe-path", "systemd-unit"))
	if c != d {
		t.Fatal("two kinds: output depends on order")
	}
	has(t, c, `(exe-path, systemd-unit)`, "both kinds kept, sorted")
}

// 회귀(검토 3): dst_node_id로만 나온 노드는 등록 목록에 있을 때만 「registered」다.
func TestTopologyPeerNodeIDNotRegistered(t *testing.T) {
	in := scenario()
	ghost := tEdge("web-01", "198.51.100.7:443", 443, cl, "", "", 1)
	ghost.DstNodeId = "ghost"
	in.Snapshots[0].Edges = append(in.Snapshots[0].Edges, ghost)
	dot, _ := inventory.RenderTopology(in)
	has(t, dot, `"node|ghost" [label="ghost\nno snapshot", shape=box`, "unregistered node id")
	if strings.Contains(dot, `"node|ghost" [label="ghost\nregistered`) {
		t.Error("a node id with no endpoint was called registered")
	}
	has(t, dot, `"node|web-03" [label="web-03\nregistered, no snapshot"`, "registered node without a snapshot")
	if len(linesFrom(dot, "node|web-01", "node|ghost")) != 1 {
		t.Error("the record with dst_node_id did not reach that node")
	}
}
