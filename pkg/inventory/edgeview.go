// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"fmt"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/posture"
)

// 엣지의 역할(v0.18.0부터 서버 쪽도 관측한다). src는 늘 관측 노드이고, role이 그 노드의 역할이다.
//
//	CLIENT       web-01 → 10.0.0.9:443          관측 노드가 연결을 열었다
//	SERVER       web-02 ← 10.0.0.1 (on :443)    관측 노드가 받았다. 상대는 클라이언트 ip(포트 없음)
//	UNSPECIFIED  web-03 ↔ 10.0.0.7 (role not confirmed)
//
// 같은 연결을 양쪽 노드가 보면 기록이 노드마다 하나씩이다. 합치지 않는다.

// edgeArrow — 관측 노드에서 본 방향.
func edgeArrow(e *discoveryv1.ObservedEdge) string {
	switch e.GetRole() {
	case discoveryv1.EdgeRole_EDGE_ROLE_CLIENT:
		return "→"
	case discoveryv1.EdgeRole_EDGE_ROLE_SERVER:
		return "←"
	}
	return "↔"
}

// edgePeer — 화면에 내는 상대. 서버 기록은 받은 포트를, 미확인 기록은 그 사실을 붙인다.
func edgePeer(e *discoveryv1.ObservedEdge) string {
	switch e.GetRole() {
	case discoveryv1.EdgeRole_EDGE_ROLE_SERVER:
		return fmt.Sprintf("%s (on :%d)", e.GetDstAddr(), e.GetPort())
	case discoveryv1.EdgeRole_EDGE_ROLE_CLIENT:
		return edgeDst(e)
	}
	return edgeDst(e) + " (role not confirmed)"
}

// roleTally — 누적 집계를 역할별로. 같은 연결을 양쪽에서 관측하면 각 쪽에 한 번씩 세어진다 — 그래서 더해 「연결 수」로 쓰지 않는다.
// 지금까지 저장된 UNSPECIFIED 기록도 「미확인」으로 센다(빠지지 않는다).
type roleTally struct{ total, pqc, classical, unknown int }

func (t *roleTally) add(e *discoveryv1.ObservedEdge) {
	t.total++
	switch posture.Classify(e.GetNegotiatedGroup(), e.GetCipher()) {
	case discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID:
		t.pqc++
	case discoveryv1.QuantumPosture_QUANTUM_POSTURE_CLASSICAL:
		t.classical++
	default:
		t.unknown++
	}
}

func (t roleTally) String() string {
	return fmt.Sprintf("%d (🟢 %d · 🔴 %d · ⚪ %d)", t.total, t.pqc, t.classical, t.unknown)
}

// roleLine — 역할별 집계 줄. 서버 쪽·미확인 기록이 하나도 없으면 빈 문자열이다(클라이언트만 관측하던 화면이 그대로다).
func roleLine(edges []*discoveryv1.ObservedEdge) string {
	var c, s, u roleTally
	for _, e := range edges {
		switch e.GetRole() {
		case discoveryv1.EdgeRole_EDGE_ROLE_CLIENT:
			c.add(e)
		case discoveryv1.EdgeRole_EDGE_ROLE_SERVER:
			s.add(e)
		default:
			u.add(e)
		}
	}
	if s.total == 0 && u.total == 0 {
		return ""
	}
	return fmt.Sprintf("   by role: client side %s · server side %s · role not confirmed %s — a connection observed from both nodes is counted once on each side\n", c, s, u)
}

// sameAppAssets — 같은 스냅샷에서 이 엣지와 **같은 비어 있지 않은 app_key**를 가진 자산. 「같은 앱 키로 관측된 라이브러리」일
// 뿐이다 — 그 연결이 그 라이브러리를 거쳤다는 근거가 아니다. 앱 키(실행 파일 경로·systemd 유닛)는 여러 프로세스가 함께
// 가질 수 있어 연결을 처리한 프로세스에 올라 있었는지도 모르고, 한 프로세스가 라이브러리를 여럿 올릴 수 있으며, 연결이
// 어느 것을 썼는지는 패킷에 없다. 판정하지 않는다.
func sameAppAssets(e *discoveryv1.ObservedEdge, findings []*discoveryv1.Finding) []string {
	key := e.GetAppKey()
	if key == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, f := range findings {
		has := false
		for _, k := range f.GetAppKeys() {
			if k == key {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		if l := assetLabel(f); l != "" && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// assetLabel — 자산을 짧게. OpenSSL은 라이브러리와 판.
func assetLabel(f *discoveryv1.Finding) string {
	switch {
	case f.GetOpenssl() != nil:
		o := f.GetOpenssl()
		return strings.TrimSpace(o.GetLib() + " " + o.GetVersion())
	case f.GetJca() != nil:
		return "JCA (" + f.GetPqcReadiness() + ")"
	case f.GetCng() != nil:
		return "CNG (" + f.GetPqcReadiness() + ")"
	}
	return ""
}
