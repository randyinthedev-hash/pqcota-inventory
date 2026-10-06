// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-discover-view — OSS 읽기전용 디스커버리 인벤토리 뷰(인벤토리 설계 §1 컴포넌트 아키텍처의 「읽기전용 뷰」).
// 각 노드가 낸 CollectionResult JSON들을 모아 발견 자산(OpenSSL·JCA)과 관측 통신 엣지(등급)를
// 그대로 보여준다. 선언 대비 3-상태 대조(reconcile)는 하지 않는다.
//
// usage: pqcota-discover-view <results-dir> [nodes.json] [topology-out.dot]
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/posture"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/resultio"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pqcota-discover-view <results-dir> [nodes.json] [topology-out.dot]")
		os.Exit(2)
	}
	dir := os.Args[1]
	var nodesPath, dotOut string
	if len(os.Args) > 2 {
		nodesPath = os.Args[2]
	}
	if len(os.Args) > 3 {
		dotOut = os.Args[3]
	} else {
		dotOut = "topology.dot"
	}

	ip2node := loadNodeMap(nodesPath)
	results := loadResults(dir)

	// 노드별 자산 + 전체 관측 엣지 수집.
	assets := map[string][]string{} // node → 자산 요약 라인
	nodeSet := map[string]bool{}
	var edges []*discoveryv1.ObservedEdge
	for _, res := range results {
		node := res.GetEnvelope().GetTargetNodeId()
		nodeSet[node] = true
		if len(res.GetObservedEdges()) > 0 || hasNetwork(res) {
			edges = append(edges, res.GetObservedEdges()...)
			continue
		}
		// 조직을 대지 않는다 — 이 저장소는 화면을 그리는 동안만 살고 아무것도 남기지 않는다.
		// 격리할 것이 없다(적재 경로는 org.FromEnv를 쓴다).
		snap, err := normalize.Normalize([]*discoveryv1.CollectionResult{res}, "snap", node, normalize.RulesetVersion, history.NewMemStore(), nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "normalize:", err)
			continue
		}
		for _, f := range snap.Findings {
			assets[node] = append(assets[node], describeFinding(f))
		}
	}

	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║  pqcota discovery view (OSS · read-only)                  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	fmt.Println("\n──────── ① discovered assets (per node) ────────")
	nodes := sortedKeys(nodeSet)
	for _, n := range nodes {
		if len(assets[n]) == 0 {
			continue
		}
		fmt.Printf("  %s\n", n)
		for _, line := range assets[n] {
			fmt.Printf("    • %s\n", line)
		}
	}

	fmt.Println("\n──────── ② observed edges + quantum-resistance grade ────────")
	pqc, classical, unknown := printEdges(edges, ip2node)
	fmt.Printf("\n  grade totals: 🟢 PQC %d · 🔴 classical %d · ⚪ unknown %d\n", pqc, classical, unknown)

	dot := renderObservedDOT(edges, ip2node)
	if err := os.WriteFile(dotOut, []byte(dot), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write dot:", err)
	} else {
		fmt.Printf("\nobserved topology written as DOT: %s (colour = grade, solid = observed). No three-state reconciliation against declarations.\n", dotOut)
	}
}

func describeFinding(f *discoveryv1.Finding) string {
	switch f.GetCryptoRuntime() {
	case commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL:
		o := f.GetOpenssl()
		v := o.GetVersion()
		if v == "" {
			v = "(version unknown)"
		}
		fork := o.GetFork()
		if fork == "" {
			fork = "OpenSSL?"
		}
		return fmt.Sprintf("OpenSSL  %s %s (%s) [%s]", o.GetLib(), v, fork, f.GetEvidenceStrength())
	case commonv1.CryptoRuntime_CRYPTO_RUNTIME_JCA:
		j := f.GetJca()
		return fmt.Sprintf("JCA provider chain: %s [%s]", strings.Join(j.GetProviderSet(), ","), f.GetEvidenceStrength())
	case commonv1.CryptoRuntime_CRYPTO_RUNTIME_WIN_CNG:
		c := f.GetCng()
		// provider 이름은 전부 Microsoft라(실측 9개) 목록만으로는 노드가 갈리지 않는다.
		// 사람이 여기서 찾는 답은 **무엇을 할 수 있나**이므로 PQC 요약을 함께 낸다.
		return fmt.Sprintf("CNG providers: %d · %d algorithms · PQC %s [%s]",
			len(c.GetProviderSet()), len(c.GetAlgorithms()), nz(f.GetPqcReadiness()), f.GetEvidenceStrength())
	default:
		return "(unknown runtime)"
	}
}

func printEdges(edges []*discoveryv1.ObservedEdge, ip2node map[string]string) (pqc, classical, unknown int) {
	type row struct {
		src, dst, proto, grp string
		p                    discoveryv1.QuantumPosture
	}
	var rows []row
	for _, e := range edges {
		dst := resolveDst(e, ip2node)
		p := posture.Classify(e.GetNegotiatedGroup(), e.GetCipher())
		switch p {
		case discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID:
			pqc++
		case discoveryv1.QuantumPosture_QUANTUM_POSTURE_CLASSICAL:
			classical++
		default:
			unknown++
		}
		grp := e.GetNegotiatedGroup()
		if grp == "" {
			grp = "(unknown)"
		}
		rows = append(rows, row{e.GetSrcNodeId(), dst, protoName(e.GetProtocol()), grp, p})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].src != rows[j].src {
			return rows[i].src < rows[j].src
		}
		return rows[i].dst < rows[j].dst
	})
	for _, r := range rows {
		grp := r.grp
		if lbl := posture.GradeLabel(posture.Grade(r.grp)); lbl != "" {
			grp = fmt.Sprintf("%s [%s]", r.grp, lbl) // PQC 그룹엔 성숙도(표준/초안/실험/취약) 병기
		}
		fmt.Printf("  %s %-10s → %-18s %-5s %s\n", posture.Symbol(r.p), r.src, r.dst, r.proto, grp)
	}
	return
}

func renderObservedDOT(edges []*discoveryv1.ObservedEdge, ip2node map[string]string) string {
	var b strings.Builder
	// rankdir=TB(위→아래) 세로 배치 + 하단 캡션 범례(옆으로 안 퍼지게). 폭 축소.
	b.WriteString("digraph crypto_observed {\n  rankdir=TB;\n  ranksep=0.5;\n  nodesep=0.3;\n")
	b.WriteString(`  labelloc="b"; fontsize=11; label="grade:  🟢 PQC/hybrid   🔴 classical = quantum-vulnerable   ⚪ unknown";` + "\n")
	b.WriteString(`  node [shape=box, style="rounded,filled", fillcolor="#eeeeff", fontname="sans"];` + "\n")
	b.WriteString(`  edge [fontname="sans", fontsize=10];` + "\n\n")
	seen := map[string]bool{}
	for _, e := range edges {
		dst := resolveDst(e, ip2node)
		key := e.GetSrcNodeId() + "|" + dst + "|" + protoName(e.GetProtocol())
		if seen[key] {
			continue
		}
		seen[key] = true
		p := posture.Classify(e.GetNegotiatedGroup(), e.GetCipher())
		color := "#999999"
		switch p {
		case discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID:
			color = "#22aa22"
		case discoveryv1.QuantumPosture_QUANTUM_POSTURE_CLASSICAL:
			color = "#cc2222"
		}
		grp := shortGroup(e.GetNegotiatedGroup())
		if lbl := posture.GradeLabel(posture.Grade(e.GetNegotiatedGroup())); lbl != "" {
			grp = grp + " (" + lbl + ")" // 표준/실험 성숙도를 그래프 라벨에도
		}
		label := fmt.Sprintf("%s %s %s", posture.Symbol(p), protoName(e.GetProtocol()), grp)
		b.WriteString(fmt.Sprintf("  %q -> %q [label=%q, color=%q, penwidth=2];\n", e.GetSrcNodeId(), dst, label, color))
	}
	b.WriteString("}\n")
	return b.String()
}

func resolveDst(e *discoveryv1.ObservedEdge, ip2node map[string]string) string {
	if e.GetDstNodeId() != "" {
		return e.GetDstNodeId()
	}
	host := e.GetDstAddr()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if n, ok := ip2node[host]; ok {
		return n
	}
	return e.GetDstAddr()
}

// shortGroup — 라벨 폭을 줄이려고 협상 그룹의 긴 접미사(@openssh.com·-sha512)를 정리한다.
func shortGroup(g string) string {
	if g == "" {
		return "unknown"
	}
	if i := strings.IndexByte(g, '@'); i > 0 {
		g = g[:i]
	}
	for _, suf := range []string{"-sha512", "-sha256", "-sha384"} {
		g = strings.TrimSuffix(g, suf)
	}
	return g
}

func protoName(p discoveryv1.NetworkProtocol) string {
	switch p {
	case discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS:
		return "TLS"
	case discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_SSH:
		return "SSH"
	case discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_QUIC:
		return "QUIC"
	default:
		return "?"
	}
}

func hasNetwork(res *discoveryv1.CollectionResult) bool {
	for _, l := range res.GetCompleteness().GetLayersCovered() {
		if l == commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK {
			return true
		}
	}
	for _, l := range res.GetCompleteness().GetLayersMissing() {
		if l == commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK {
			return true
		}
	}
	return false
}

// nodes.json: [{"name":"node-web","ips":["10.0.0.2"]}, ...] — 관측 IP→노드명 잇기(가독성).
func loadNodeMap(path string) map[string]string {
	m := map[string]string{}
	if path == "" {
		return m
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	var nodes []struct {
		Name string   `json:"name"`
		IPs  []string `json:"ips"`
	}
	if json.Unmarshal(b, &nodes) != nil {
		return m
	}
	for _, n := range nodes {
		for _, ip := range n.IPs {
			m[ip] = n.Name
		}
	}
	return m
}

// loadResults — 결과 디렉터리를 읽는다. 형식 판별은 공용 디코더에 맡긴다(pkg/inventory/resultio).
//
// 여기서 직접 `*.json`만 훑고 단일 객체로만 읽던 때, JVM이 둘 이상인 노드의 JCA 결과가
// **통째로 화면에서 빠졌다.** 그 파일은 JSON Lines였는데 단일 객체로 파싱해 보고 실패하면
// 알리지 않고 건너뛰었기 때문이다. 관측이 화면까지 오지 않으면 적지 않은 것과 같다.
//
// 못 읽은 입력에서 멈추지는 않는다. 이쪽은 조회용 뷰라 나머지라도 그리는 편이 낫다.
// 대신 **무엇이 빠졌는지 반드시 알린다** — 적재 관문(pqcota-ingest)은 같은 자리에서 멈춘다.
func loadResults(dir string) []*discoveryv1.CollectionResult {
	out, flaws := resultio.LoadDir(dir)
	for _, f := range flaws {
		fmt.Fprintln(os.Stderr, "[discover-view] ⚠ left out of the view:", f)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

// nz — 빈 값을 unknown으로. 파생이 비었는데 빈칸으로 두면 "PQC 없음"으로 읽힌다(§2.5).
func nz(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
