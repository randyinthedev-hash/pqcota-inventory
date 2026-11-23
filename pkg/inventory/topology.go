// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/posture"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// 토폴로지(-topology, 계획 2026-11-23-inventory-topology). 저장된 관측을 **그대로** 그린다.
//
//   - 선 하나 = 관측 기록 하나. 양쪽 노드가 같은 연결을 관측하면 선 둘이다 — 짝짓지 않고, 횟수(×)는 그
//     기록의 것이다(더하지 않는다). 앱 키는 관측한 쪽의 값이라 관측 노드 쪽 끝에만 붙인다.
//   - CLIENT는 관측 노드 → 상대, SERVER는 상대 → 관측 노드, 역할 미확인은 화살표 없는 점선.
//   - 상대 IP는 등록 정보에서 **정확히 한 노드에만** 대응할 때 그 노드로 잇는다. 아니면 주소 상자.
//   - 앱과 라이브러리는 같은 노드·같은 스냅샷에서 비어 있지 않은 앱 키가 일치할 때만 잇는다(사용의 근거가 아니다).
//   - 노드마다 시각은 **마지막 적재 시각**이다(관측 시각이 아니다 — 같은 결과를 다시 적재하면 갱신된다).

// NodeTime — 노드 클러스터에 적는 시각. Loaded면 마지막 적재 시각, 아니면(관측 기록이 없는 옛 이력) 스냅샷 생성 시각.
type NodeTime struct {
	At     time.Time
	Loaded bool
}

// TopologyInput — 노드마다의 현재 스냅샷, 그 시각, 등록 엔드포인트.
type TopologyInput struct {
	Snapshots []*history.Snapshot
	Times     map[string]NodeTime // node_id → 시각
	Endpoints []*inventoryv1.MachineEndpoint
}

// TopologySummary — 그린 것의 수(명령이 한 줄로 알린다).
type TopologySummary struct {
	Nodes, Edges, Addresses int
}

// LoadTopology — 저장소에서 노드마다 현재 스냅샷(Latest)과 마지막 적재 시각을 읽는다. eps는 nil이어도 된다(그러면
// 상대는 모두 주소로 그려진다).
func LoadTopology(store history.Store, eps EndpointLister) (TopologyInput, error) {
	in := TopologyInput{Times: map[string]NodeTime{}}
	nodes, err := store.Nodes()
	if err != nil {
		return in, err
	}
	for _, n := range nodes {
		snap, err := store.Latest(n)
		if err != nil {
			return in, err
		}
		if snap == nil {
			continue
		}
		stats, err := store.ObservationStats(n)
		if err != nil {
			return in, err
		}
		in.Snapshots = append(in.Snapshots, snap)
		if st, ok := stats[snap.ID]; ok && !st.Last.IsZero() {
			in.Times[n] = NodeTime{At: st.Last, Loaded: true}
		} else {
			in.Times[n] = NodeTime{At: snap.CreatedAt}
		}
	}
	if eps != nil {
		if in.Endpoints, err = eps.Endpoints(); err != nil {
			return in, err
		}
	}
	return in, nil
}

// RenderTopology — DOT. 같은 입력이면 같은 바이트다(노드·선을 정렬한다).
func RenderTopology(in TopologyInput) (string, TopologySummary) {
	snaps := append([]*history.Snapshot(nil), in.Snapshots...)
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].NodeID < snaps[j].NodeID })

	names := map[string]string{}
	byIP := map[string][]string{}
	for _, ep := range in.Endpoints {
		if ep.GetName() != "" {
			names[ep.GetNodeId()] = ep.GetName()
		}
		if ip := normIP(ep.GetIp()); ip != "" && !contains(byIP[ip], ep.GetNodeId()) {
			byIP[ip] = append(byIP[ip], ep.GetNodeId())
		}
	}
	observed := map[string]bool{}
	for _, s := range snaps {
		observed[s.NodeID] = true
	}

	var b strings.Builder
	b.WriteString("digraph pqcota_topology {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString(`  graph [fontname="sans", labelloc=t, label=` + dq("pqcota topology — observed connections as stored in the inventory\neach node shows its current snapshot; load times differ per node") + "];\n")
	b.WriteString(`  node [fontname="sans"];` + "\n")
	b.WriteString(`  edge [fontname="sans", fontsize=10];` + "\n")

	var sum TopologySummary
	standalone := map[string]bool{} // 상대로만 나온 등록 노드(스냅샷 없음)
	addrs := map[string]string{}    // 주소 상자 id → 라벨
	var edgeLines []string

	for i, s := range snaps {
		sum.Nodes++
		node := s.NodeID
		title := node
		if nm := names[node]; nm != "" && nm != node {
			title = fmt.Sprintf("%s (%s)", node, nm)
		}
		when := "time unknown"
		if t, ok := in.Times[node]; ok && !t.At.IsZero() {
			if t.Loaded {
				when = "last loaded " + t.At.UTC().Format(time.RFC3339)
			} else {
				when = "snapshot created " + t.At.UTC().Format(time.RFC3339)
			}
		}
		fmt.Fprintf(&b, "  subgraph cluster_%d {\n", i)
		fmt.Fprintf(&b, "    label=%s;\n    style=rounded; color=\"#888888\";\n", dq(title+"\n"+when+"\nsnapshot "+short12(s.ID)))
		fmt.Fprintf(&b, "    %s [label=%s, shape=box, style=\"rounded,filled\", fillcolor=\"#eeeeff\"];\n", dq(nodeID(node)), dq(node))

		// 앱: 이 스냅샷의 엣지에 나온 비어 있지 않은 앱 키.
		type app struct{ key, kind string }
		apps := map[string]app{}
		for _, e := range s.Edges {
			if k := e.GetAppKey(); k != "" {
				apps[k] = app{k, e.GetAppKeyKind()}
			}
		}
		keys := make([]string, 0, len(apps))
		for k := range apps {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		libs := map[string]bool{}
		var libLines []string
		for _, k := range keys {
			a := apps[k]
			label := a.key
			if a.kind != "" {
				label += "\n(" + a.kind + ")"
			}
			fmt.Fprintf(&b, "    %s [label=%s, shape=component];\n", dq(appID(node, k)), dq(label))
			for _, l := range assetsWithAppKey(k, s.Findings) {
				libs[l] = true
				libLines = append(libLines, fmt.Sprintf("    %s -> %s [style=dotted, arrowhead=none, color=\"#666666\"];\n", dq(appID(node, k)), dq(libID(node, l))))
			}
		}
		libNames := make([]string, 0, len(libs))
		for l := range libs {
			libNames = append(libNames, l)
		}
		sort.Strings(libNames)
		for _, l := range libNames {
			fmt.Fprintf(&b, "    %s [label=%s, shape=ellipse, style=filled, fillcolor=\"#f6f6f6\"];\n", dq(libID(node, l)), dq(l))
		}
		sort.Strings(libLines)
		for _, l := range libLines {
			b.WriteString(l)
		}
		b.WriteString("  }\n")

		// 선: 관측 기록 하나에 하나.
		for _, e := range s.Edges {
			sum.Edges++
			local := nodeID(node)
			if k := e.GetAppKey(); k != "" {
				local = appID(node, k)
			}
			peer, peerLabel, isNode := resolvePeer(e, byIP)
			if isNode {
				if !observed[peer] {
					standalone[peer] = true
				}
				peer = nodeID(peer)
			} else {
				addrs[peer] = peerLabel
			}
			edgeLines = append(edgeLines, topologyEdgeLine(e, node, local, peer))
		}
	}

	// 상대로만 나온 등록 노드(스냅샷 없음)와 주소 상자.
	var extra []string
	for n := range standalone {
		sum.Nodes++
		label := n
		if nm := names[n]; nm != "" && nm != n {
			label = fmt.Sprintf("%s (%s)", n, nm)
		}
		extra = append(extra, fmt.Sprintf("  %s [label=%s, shape=box, style=\"rounded,dashed\"];\n", dq(nodeID(n)), dq(label+"\nregistered, no snapshot")))
	}
	for id, label := range addrs {
		sum.Addresses++
		extra = append(extra, fmt.Sprintf("  %s [label=%s, shape=note];\n", dq(id), dq(label)))
	}
	sort.Strings(extra)
	for _, l := range extra {
		b.WriteString(l)
	}
	sort.Strings(edgeLines)
	for _, l := range edgeLines {
		b.WriteString(l)
	}

	b.WriteString("  subgraph cluster_legend {\n")
	b.WriteString("    label=\"legend\"; style=rounded; color=\"#bbbbbb\";\n")
	b.WriteString("    \"legend\" [shape=plaintext, label=" + dq(strings.Join([]string{
		"solid arrow: a connection the observing node opened (observing node -> peer)",
		"  or accepted (peer -> observing node)",
		"dashed, no arrow: role not confirmed",
		"dotted: library observed with the same app key (not evidence that the connection used it)",
		"one line = one stored record; a connection observed on both nodes is two lines,",
		"  and xN is that record's count (not summed)",
		"green: PQC/hybrid · red: classical · grey: unknown",
		"note box: an address that is unregistered or shared by several registered nodes",
	}, "\n")) + "];\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), sum
}

// topologyEdgeLine — 관측 기록 하나의 선. 방향은 역할을 따른다.
func topologyEdgeLine(e *discoveryv1.ObservedEdge, observer, local, peer string) string {
	role := "role not confirmed"
	from, to, extra := local, peer, `, style=dashed, dir=none`
	switch e.GetRole() {
	case discoveryv1.EdgeRole_EDGE_ROLE_CLIENT:
		role, extra = "client", ""
	case discoveryv1.EdgeRole_EDGE_ROLE_SERVER:
		role, from, to, extra = "server", peer, local, ""
	}
	parts := []string{short(e.GetProtocol().String(), "NETWORK_PROTOCOL_")}
	if p := e.GetPort(); p != 0 {
		parts[0] += fmt.Sprintf(" :%d", p)
	}
	if g := e.GetNegotiatedGroup(); g != "" {
		parts = append(parts, g)
	} else {
		parts = append(parts, "group unknown")
	}
	if c := e.GetObservedCount(); c > 0 {
		parts = append(parts, fmt.Sprintf("×%d", c))
	} else {
		parts = append(parts, "count not recorded")
	}
	label := strings.Join(parts, " · ") + "\nseen by " + observer + " as " + role
	color := "#999999"
	switch posture.Classify(e.GetNegotiatedGroup(), e.GetCipher()) {
	case discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID:
		color = "#22aa22"
	case discoveryv1.QuantumPosture_QUANTUM_POSTURE_CLASSICAL:
		color = "#cc2222"
	}
	return fmt.Sprintf("  %s -> %s [label=%s, color=%q, penwidth=2%s];\n", dq(from), dq(to), dq(label), color, extra)
}

// resolvePeer — 상대. 노드면 (node_id, "", true), 아니면 (주소 상자 id, 라벨, false).
func resolvePeer(e *discoveryv1.ObservedEdge, byIP map[string][]string) (string, string, bool) {
	if d := e.GetDstNodeId(); d != "" {
		return d, "", true
	}
	ip := peerIP(e)
	if ip == "" {
		return "addr|" + e.GetDstAddr(), e.GetDstAddr() + "\nnot an IP address", false
	}
	switch ns := byIP[ip]; len(ns) {
	case 1:
		return ns[0], "", true
	case 0:
		return "addr|" + ip, ip + "\nunregistered", false
	default:
		return "addr|" + ip, fmt.Sprintf("%s\nIP shared by %d registered nodes", ip, len(ns)), false
	}
}

// peerIP — 엣지의 상대 IP(정규화). 역할을 다 믿지 않고 꼴로 읽는다. 이전 판의 기록은 역할과 dst_addr의 꼴이 맞지
// 않을 수 있다(역할이 없는데 "10.0.1.99:22", v0.1.0부터 SERVER가 잘못 붙은 클라이언트 기록의 "ip:port").
//
//   - CLIENT는 만들어질 때부터 "ip:port"다. 괄호 없는 IPv6("fd00::20:8443")는 문자열 전체가 다른 IPv6로도 읽히므로
//     끝의 ":<port>"를 먼저 뗀다.
//   - 그 밖의 역할은 먼저 전체가 IP인지 보고(SERVER·미확인의 지금 꼴), 아니면 ":<port>"를 떼어 본다(옛 기록).
//   - 마지막으로 net.SplitHostPort(포트가 port 필드와 다를 때). 다 아니면 "".
func peerIP(e *discoveryv1.ObservedEdge) string {
	a := strings.TrimSpace(e.GetDstAddr())
	stripPort := func() string {
		if p := e.GetPort(); p != 0 {
			if suf := ":" + strconv.Itoa(int(p)); strings.HasSuffix(a, suf) {
				return normIP(strings.TrimSuffix(a, suf))
			}
		}
		return ""
	}
	if e.GetRole() == discoveryv1.EdgeRole_EDGE_ROLE_CLIENT {
		if ip := stripPort(); ip != "" {
			return ip
		}
	}
	if ip := normIP(a); ip != "" {
		return ip
	}
	if ip := stripPort(); ip != "" {
		return ip
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		return normIP(h)
	}
	return ""
}

// normIP — IP 표기를 하나로(괄호를 떼고, IPv4·::ffff: 매핑은 a.b.c.d로). IP가 아니면 "".
func normIP(s string) string {
	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "["), "]")
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func nodeID(n string) string       { return "node|" + n }
func appID(n, key string) string   { return "app|" + n + "|" + key }
func libID(n, label string) string { return "lib|" + n + "|" + label }

func short12(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// dq — DOT의 따옴표 문자열. 백슬래시·따옴표를 이스케이프하고, 줄바꿈은 DOT의 \n으로 적는다.
func dq(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}
