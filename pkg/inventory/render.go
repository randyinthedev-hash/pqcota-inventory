// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

// Package inventory — 읽기전용 인벤토리 뷰를 그린다(인벤토리 설계 §1 컴포넌트 아키텍처, Phase 0 산출물).
// 스냅샷의 파생 Finding + 완전성 갭을 사람이 읽는 텍스트로. 판단은 하지 않는다(§2.1).
package inventory

import (
	"fmt"
	"sort"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/posture"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/declaration"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// Render — 읽기전용 인벤토리 뷰. 갭은 "부재"가 아니라 "원리상 관측하지 못함"으로 명시(§2.6).
func Render(snap *history.Snapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "node %s  (snapshot %s · ruleset %s)\n", snap.NodeID, snap.ID, snap.RulesetVersion)
	fmt.Fprintf(&b, "%-8s %-12s %-22s %-28s %s\n", "runtime", "evidence", "detection", "detail", "id")
	for _, f := range snap.Findings {
		detail := detailOf(f)
		id := shortID(f.GetId())
		fmt.Fprintf(&b, "%-8s %-12s %-22s %-28s %s\n",
			short(f.GetCryptoRuntime().String(), "CRYPTO_RUNTIME_"),
			short(f.GetEvidenceStrength().String(), "EVIDENCE_STRENGTH_"),
			short(f.GetDetectionMethod().String(), "DETECTION_METHOD_"),
			detail, id)
	}
	if snap.ExcludedByScope > 0 {
		// 제외는 "없음"이 아니다 — 정책으로 뺀 걸 감추면 인벤토리가 거짓말한다(§2.6).
		fmt.Fprintf(&b, "excluded by asset scope: %d (observed but out of management scope — not absence)\n", snap.ExcludedByScope)
	}
	if c := snap.Completeness; c != nil {
		if len(c.GetLayersMissing()) > 0 {
			var g []string
			for _, l := range c.GetLayersMissing() {
				g = append(g, short(l.String(), "COLLECTION_LAYER_"))
			}
			fmt.Fprintf(&b, "gap (unobservable by design != absent): %s  %s\n", strings.Join(g, ","), c.GetNote())
		} else if n := c.GetNote(); n != "" {
			// **계층 갭이 없어도 노트는 낸다.** 계층이 빈 노트를 흘려보내던 탓에, 구간이 중간에
			// 끊겼다는 netcap의 경고와 앱을 못 짚은 것이 화면까지 오지 못했다 — 정직하게 적어 둔
			// 것이 읽는 사람에게 도달하지 않으면 적지 않은 것과 같다(§2.6).
			fmt.Fprintf(&b, "observation limit: %s\n", n)
		}
	}
	return b.String()
}

// detailOf — finding의 런타임별 상세 한 줄. Render와 diff가 같은 문자열을 봐야
// "무엇이 달라졌나"가 화면과 어긋나지 않는다.
func detailOf(f *discoveryv1.Finding) string {
	detail := "-"
	switch {
	case f.GetOpenssl() != nil:
		detail = fmt.Sprintf("%s/%s %s [%s]", f.GetOpenssl().GetLib(), nz(f.GetOpenssl().GetFork()),
			f.GetOpenssl().GetVersion(), short(f.GetOpenssl().GetBindingMode().String(), "OPENSSL_BINDING_MODE_"))
	case f.GetJca() != nil:
		detail = fmt.Sprintf("providers=%d %s", len(f.GetJca().GetProviderSet()), f.GetPqcReadiness())
	case f.GetCng() != nil:
		// JCA와 같은 모양. 알고리즘 개수를 함께 내는 이유는 CNG의 provider 이름이 전부
		// Microsoft라 개수만으로는 노드가 갈리지 않기 때문이다(실측: 9개가 전부 같은 벤더).
		detail = fmt.Sprintf("providers=%d algorithms=%d %s",
			len(f.GetCng().GetProviderSet()), len(f.GetCng().GetAlgorithms()), f.GetPqcReadiness())
	}
	if ak := f.GetAppKeys(); len(ak) > 0 {
		detail += "  @" + strings.Join(ak, ",") // 자산이 어느 앱 것인지(§1.5) — 공유 .so면 다중 앱
	}
	return detail
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func gapOf(snap *history.Snapshot) string {
	c := snap.Completeness
	if c == nil || len(c.GetLayersMissing()) == 0 {
		return "-"
	}
	var g []string
	for _, l := range c.GetLayersMissing() {
		g = append(g, short(l.String(), "COLLECTION_LAYER_"))
	}
	return strings.Join(g, ",")
}

// Plural — 수와 단위를 영어 어법에 맞춰 붙인다. 1이면 단수다.
// 화면에 나온 "1 change points"는 그대로 문서의 샘플 출력이 되므로 눈에 띈다.
func Plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// RenderHistory — 한 노드의 **변화 지점**을 오래된 것부터 나열한다. 스냅샷은 실질 내용이
// 바뀔 때만 쌓이므로, 각 줄은 "이 상태였던 구간"이고 obs 열이 그동안 몇 번 관측했는지 보여준다.
// 관측 사실 서술이지 판정이 아니다 — 변화가 선언과 맞는지·의미 있는지는 판정이라 하지 않는다(아키텍처 §6).
func RenderHistory(nodeID string, snaps []*history.Snapshot, stats map[string]history.ObsStat,
	pruned []history.RetentionEvent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "node %s — %s (oldest first)\n", nodeID, Plural(len(snaps), "change point"))
	// 절단이 있었으면 먼저 고지한다 — 안 그러면 이력의 구멍이 "관측을 안 함"으로 읽힌다(§2.6 정신).
	for _, e := range pruned {
		fmt.Fprintf(&b, "⌫ pruned by the retention policy: %[2]s before %[1]s (%[3]s, %[4]s · run %[5]s)\n",
			e.PrunedUpTo.Format("2006-01-02 15:04:05"), Plural(e.Snapshots, "change point"), e.Policy,
			Plural(e.Observations, "observation"), e.ExecutedAt.Format("2006-01-02"))
	}
	b.WriteByte('\n')
	if len(snaps) == 0 {
		b.WriteString("(no snapshot ingested)\n")
		return b.String()
	}
	// 컬럼 헤더는 영문 — 한글은 터미널에서 2배 폭이라 고정폭 칸 정렬이 깨진다(Render와 같은 방식).
	// snapshot은 길이가 들쭉날쭉하고 **자르면 안 되는** 값(사용자가 -snapshot·-diff에 그대로 붙여넣는
	// 손잡이)이라 맨 뒤에 통째로 둔다.
	fmt.Fprintf(&b, "%-6s %-19s %-13s %8s %6s %5s %-24s %-18s %s\n",
		"seq", "changed", "ruleset", "findings", "edges", "obs", "observed", "gap", "snapshot")
	for _, s := range snaps {
		obs, window := "-", "-"
		if st, ok := stats[s.ID]; ok {
			obs = fmt.Sprintf("%d", st.Count)
			window = st.First.Format("01-02 15:04") + "~" + st.Last.Format("01-02 15:04")
		}
		fmt.Fprintf(&b, "%-6d %-19s %-13s %8d %6d %5s %-24s %-18s %s\n",
			s.Seq, s.CreatedAt.Format("2006-01-02 15:04:05"), s.RulesetVersion,
			len(s.Findings), len(s.Edges), obs, window, gapOf(s), s.ID)
	}
	b.WriteString("\n(snapshots accumulate only when the content changes — obs/observed show how often and until when that state was re-confirmed.\n")
	b.WriteString(" gap = a layer that cannot be observed by design, not \"absent\". Pass the snapshot value straight to -snapshot/-diff.)\n")
	return b.String()
}

// RenderDetail — 스냅샷 단건 상세: 자산 뷰 + 그 스냅샷의 관측 엣지.
// (Render는 누적 뷰가 쓰므로 건드리지 않고, 엣지는 상세에서만 펼친다.)
func RenderDetail(snap *history.Snapshot) string {
	return RenderDetailWith(snap, nil)
}

// RenderDetailWith — 사람이 선언한 앱을 얹어 낸다. overlay가 nil이면 [RenderDetail]과 같다.
//
// 얹는 일은 **읽을 때만** 일어난다 — 저장된 관측 엣지는 그대로다(검토 중인 설계 §7.5).
func RenderDetailWith(snap *history.Snapshot, overlay *AttributionOverlay) string {
	var b strings.Builder
	b.WriteString(Render(snap))
	if len(snap.Edges) == 0 {
		return b.String()
	}
	fmt.Fprintf(&b, "\n%d observed edges (this snapshot)\n", len(snap.Edges))
	declared := 0
	for _, e := range snap.Edges {
		key, kind := overlay.Apply(e)
		if kind == declaration.KindDeclared {
			declared++
		}
		fmt.Fprintf(&b, "  %s → %-22s %-5s %-38s %s%s\n",
			e.GetSrcNodeId(), edgeDst(e), short(e.GetProtocol().String(), "NETWORK_PROTOCOL_"),
			edgeAlgo(e), postureMark(e), appMark(key, kind))
	}
	if declared > 0 {
		// 몇 개가 선언으로 메워졌는지 밝힌다 — 화면만 보면 관측과 구별되지 않는다.
		fmt.Fprintf(&b, "  (%d of them are not observations but **apps declared by a person** — marked `(declared)`)\n", declared)
	}
	return b.String()
}

// edgeApp — 엣지를 연 앱. 사람이 조치할 대상은 서버가 아니라 앱이다.
//
// **비어 있으면 "어느 앱인지 밝히지 못함"이지 "앱 없음"이 아니다.** 그래서 빈칸으로 두지 않고 `@?`로
// 적는다 — 빈칸은 열이 없는 것과 구별되지 않는다. 왜 못 잡았는지는 그 스냅샷의 완전성 노트에
// 있다(§2.6).
//
// 근거(`app_key_kind`)가 유닛이 아니면 함께 적는다. systemd 유닛은 앱 이름이지만 exe 경로는
// 그렇지 않아서, 같은 값이라도 얼마나 믿을지가 다르다.
func appMark(key, kind string) string {
	if key == "" {
		return "  @?"
	}
	if kind != "" && kind != "systemd-unit" {
		return "  @" + key + "(" + kind + ")"
	}
	return "  @" + key
}

// RenderDiff — 두 스냅샷 사이의 변화를 관측 사실로만 서술한다(추가·사라짐·변경).
// finding id는 (node|name|runtime|fork) 해시라 버전이 바뀌어도 유지된다 → 같은 자산의 변경으로 잡힌다.
func RenderDiff(a, b *history.Snapshot) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "changes (node %s)\n  %s\n  → %s\n", b.NodeID, a.ID, b.ID)
	fmt.Fprintf(&sb, "  %s (seq %d, ruleset %s)  →  %s (seq %d, ruleset %s)\n\n",
		a.CreatedAt.Format("2006-01-02 15:04:05"), a.Seq, a.RulesetVersion,
		b.CreatedAt.Format("2006-01-02 15:04:05"), b.Seq, b.RulesetVersion)
	if a.RulesetVersion != b.RulesetVersion {
		sb.WriteString("⚠ the rulesets differ — a difference in derived values (evidence, pqc_readiness) may be a recomputation, not a real change (§1.2).\n\n")
	}
	// 방향 규약: 첫 인자=과거, 둘째=최신. '추가'=둘째에만·'사라짐'=첫째에만이라, 인자를 시간
	// 역순으로 주면 방향이 뒤집혀 읽힌다 — 하드 에러는 아니다(되돌림 미리보기로 역순 비교가
	// 유효하므로). 대신 뒤집혔음을 고지한다(§2.6 — 오독을 그대로 두지 않는다).
	if a.CreatedAt.After(b.CreatedAt) {
		sb.WriteString("⚠ the first snapshot is the newer one (reverse order) — 'added' then reads as removed and 'removed' as added. In time order it is <older-id>,<newer-id>.\n\n")
	}

	am, bm := indexFindings(a.Findings), indexFindings(b.Findings)
	var added, removed, changed []string
	for _, id := range sortedKeys(bm) {
		f := bm[id]
		old, ok := am[id]
		switch {
		case !ok:
			added = append(added, fmt.Sprintf("  + %-8s %s  %s",
				short(f.GetCryptoRuntime().String(), "CRYPTO_RUNTIME_"), detailOf(f), shortID(id)))
		case detailOf(old) != detailOf(f) || old.GetEvidenceStrength() != f.GetEvidenceStrength():
			changed = append(changed, fmt.Sprintf("  ~ %s  %s\n      → %s", shortID(id), diffLine(old), diffLine(f)))
		}
	}
	for _, id := range sortedKeys(am) {
		if _, ok := bm[id]; !ok {
			f := am[id]
			removed = append(removed, fmt.Sprintf("  - %-8s %s  %s",
				short(f.GetCryptoRuntime().String(), "CRYPTO_RUNTIME_"), detailOf(f), shortID(id)))
		}
	}

	section(&sb, "added", added)
	section(&sb, "removed", removed)
	section(&sb, "changed", changed)
	if len(added)+len(removed)+len(changed) == 0 {
		fmt.Fprintf(&sb, "no asset changes (%d identical on both sides)\n", len(bm))
	}
	if la, lb := len(a.Edges), len(b.Edges); la != lb {
		fmt.Fprintf(&sb, "\nobserved edges: %d → %d\n", la, lb)
	}
	if ga, gb := gapOf(a), gapOf(b); ga != gb {
		fmt.Fprintf(&sb, "gap (unobservable by design): %s → %s\n", ga, gb)
	}
	return sb.String()
}

func section(b *strings.Builder, title string, lines []string) {
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(b, "%s %d\n", title, len(lines))
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	b.WriteByte('\n')
}

func diffLine(f *discoveryv1.Finding) string {
	return fmt.Sprintf("%s [%s]", detailOf(f), short(f.GetEvidenceStrength().String(), "EVIDENCE_STRENGTH_"))
}

func indexFindings(fs []*discoveryv1.Finding) map[string]*discoveryv1.Finding {
	m := make(map[string]*discoveryv1.Finding, len(fs))
	for _, f := range fs {
		m[f.GetId()] = f
	}
	return m
}

func sortedKeys(m map[string]*discoveryv1.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out) // 결정론적 출력
	return out
}

func edgeDst(e *discoveryv1.ObservedEdge) string {
	d := e.GetDstNodeId()
	if d == "" {
		return e.GetDstAddr() // 스코프에 잇지 못함(off-scope) — 원시 주소로 표기(§1.4)
	}
	if p := e.GetPort(); p != 0 {
		return fmt.Sprintf("%s:%d", d, p)
	}
	return d
}

func edgeAlgo(e *discoveryv1.ObservedEdge) string {
	g, c := e.GetNegotiatedGroup(), e.GetCipher()
	switch {
	case g != "" && c != "":
		return g + " / " + c
	case g != "":
		return g
	case c != "":
		return c
	}
	return "-"
}

func postureMark(e *discoveryv1.ObservedEdge) string {
	switch posture.Classify(e.GetNegotiatedGroup(), e.GetCipher()) {
	case discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID:
		return "🟢 PQC/hybrid"
	case discoveryv1.QuantumPosture_QUANTUM_POSTURE_CLASSICAL:
		return "🔴 classical"
	default:
		return "⚪ unknown"
	}
}

func short(s, prefix string) string { return strings.ToLower(strings.TrimPrefix(s, prefix)) }

func nz(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
