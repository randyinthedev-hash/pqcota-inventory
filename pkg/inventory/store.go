// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"fmt"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/posture"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// RenderStore — 히스토리 저장소에 누적된 전 노드의 최신 스냅샷을 읽어 중앙 인벤토리 뷰를 낸다.
// pqcota-ingest가 적재한 것을 조회 — 파일 취합(휘발성)과 달리 append-only 영속에서 읽는다(§2.4⑥).
// meta(nil 허용)가 있으면 노드별로 사람-대면 엔드포인트·프로필을 헤더에 곁들인다(인벤토리 설계 §2.0).
// 여전히 읽기전용·무판단(§2.1). 대조·판정은 하지 않는다.
func RenderStore(store history.Store, meta MetaStore) (string, error) {
	nodes, err := store.Nodes()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "═══ central inventory (cumulative · %d nodes) ═══\n\n", len(nodes))

	totalAssets := 0
	var edges []*discoveryv1.ObservedEdge
	for _, n := range nodes {
		snap, err := store.Latest(n)
		if err != nil {
			return "", err
		}
		if snap == nil {
			continue
		}
		if h := metaHeader(meta, n); h != "" {
			b.WriteString(h)
		}
		b.WriteString(Render(snap))
		b.WriteByte('\n')
		totalAssets += len(snap.Findings)
		edges = append(edges, snap.Edges...)
	}

	pqc, classical, unknown := 0, 0, 0
	for _, e := range edges {
		switch posture.Classify(e.GetNegotiatedGroup(), e.GetCipher()) {
		case discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID:
			pqc++
		case discoveryv1.QuantumPosture_QUANTUM_POSTURE_CLASSICAL:
			classical++
		default:
			unknown++
		}
	}
	fmt.Fprintf(&b, "── totals: %d assets · %d observed edges (🟢 PQC %d · 🔴 classical %d · ⚪ unknown %d) ──\n",
		totalAssets, len(edges), pqc, classical, unknown)
	return b.String(), nil
}

// metaHeader — 노드의 사람-대면 메타데이터(엔드포인트·프로필)를 한두 줄로. 없으면 빈 문자열.
func metaHeader(meta MetaStore, nodeID string) string {
	if meta == nil {
		return ""
	}
	var parts []string
	if ep, _ := meta.Endpoint(nodeID); ep != nil {
		loc := ep.GetName()
		if ep.GetIp() != "" {
			loc = fmt.Sprintf("%s (%s:%d)", loc, ep.GetIp(), ep.GetPort())
		}
		parts = append(parts, strings.TrimSpace(loc))
	}
	if pr, _ := meta.Profile(nodeID); pr != nil {
		var seg []string
		if pr.GetDisplayName() != "" {
			seg = append(seg, pr.GetDisplayName())
		}
		if e := short(pr.GetEnvironment().String(), "ENVIRONMENT_"); e != "unspecified" && e != "" {
			seg = append(seg, e)
		}
		if pr.GetRole() != "" {
			seg = append(seg, pr.GetRole())
		}
		if pr.GetOwner() != "" {
			seg = append(seg, "owner="+pr.GetOwner())
		}
		if len(seg) > 0 {
			parts = append(parts, strings.Join(seg, " · "))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "▸ " + strings.Join(parts, "  │  ") + "\n"
}
