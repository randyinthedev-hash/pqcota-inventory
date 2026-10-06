// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/scope"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"google.golang.org/protobuf/proto"
)

// Normalize — 정규화 파이프라인 후단(§2.4 ③~⑥). 한 노드에 대한 CollectionResult들을
// 강화(Finding 파생) → 동일성 해소(dedup) → **자산 스코프 게이트** → 완전성 병합 → 스냅샷 →
// 히스토리 append 한다.
//
// policy가 nil이면 전부 관리 대상이다. 제외분은 버려지되 **세어서 스냅샷에 남긴다** —
// 표시 없이 사라지면 인벤토리가 "그런 자산은 없다"고 거짓말한다(§2.6 제외 ≠ 부재).
//
// 결정론적: 같은 입력 + 같은 rulesetVersion → 같은 finding id(§1.2 재현성).
// RulesetVersion — **이 리포의 강화 규칙 판**이다. 파생값(`evidence_strength`·`pqc_readiness`·
// 등급·성숙도)을 만드는 규칙이 바뀔 때만 올린다.
//
// **릴리스 버전과 같지 않다.** 문구를 고치거나 CLI를 더한다고 파생 결과가 달라지지 않는다.
// 반대로 같은 관측에서 나오는 값이 달라지면 그것은 규칙이 바뀐 것이고, 그때 스냅샷을 가르는
// 근거가 이 문자열이다(§1.2 파생은 원본에서 재계산). 이력 비교가 「규칙이 달라 파생값이
// 움직인 것인지 실제 변화인지」를 이 값으로 가른다.
//
// 소비하는 쪽은 자기 규칙 판을 여기에 이어 붙인다 — 대조·계획 변환은 이 리포의 규칙이 아니다.
//
// v2 — 노드별 병합이 결정론적이 됐다. 결과를 시각·수집기·내용순으로 정렬하고, 같은 finding은
// 내용이 다르면 최근 것을 남기며 알리고, 엣지 동일성이 안정 필드 전부가 됐고, 완전성의 계층은
// 정렬하고 note는 전부 잇는다. 같은 입력에서 v1과 다른 스냅샷이 나오므로 판을 올렸다.
const RulesetVersion = "pqcota-enrich/v2"

func Normalize(results []*discoveryv1.CollectionResult, snapshotID, nodeID, rulesetVersion string,
	store history.Store, policy *scope.AssetPolicy) (*history.Snapshot, error) {
	// **입력 순서에 기대지 않는다.** 결과 파일이 디렉터리에서 어떤 순서로 오든 같은 스냅샷이
	// 나와야 다른 자리(다운스트림)에서 같은 결과로 같은 지문을 낼 수 있다. 시각이 첫 키라
	// 「뒤의 것 = 가장 최근」이 수집기를 가리지 않고 선다.
	results = sortResults(results)

	byID := make(map[string]int) // finding id → findings의 자리
	var findings []*discoveryv1.Finding
	var comp *commonv1.Completeness
	var conflicts []string

	byEdge := make(map[string]int) // 엣지 동일성 키 → edges의 자리
	var edges []*discoveryv1.ObservedEdge

	for _, res := range results {
		fs, err := DeriveFindings(res, snapshotID, rulesetVersion)
		if err != nil {
			return nil, err
		}
		for _, f := range fs {
			i, dup := byID[f.GetId()]
			if !dup {
				byID[f.GetId()] = len(findings)
				findings = append(findings, f)
				continue
			}
			// 같은 finding id가 두 결과에 있다(§2.4⑤ dedup). 내용이 같으면 하나다. 다르면
			// **최근 것**을 남기되 **알리지 않고 고르지 않는다** — 두 수집기가 같은 자산을 다르게 봤다는
			// 사실은 완전성 note에 남아 사람이 본다.
			if !proto.Equal(findings[i], f) {
				conflicts = append(conflicts, fmt.Sprintf("finding %s differs between collectors; kept the most recent (%s)",
					f.GetId(), res.GetEnvelope().GetCollectorId()))
				findings[i] = f
			}
		}
		// 관측 통신 엣지(network-collector, 인벤토리 설계 §6)도 스냅샷 관측 레인에 싣는다. 노드 내부 자산과 별도.
		for _, e := range res.GetObservedEdges() {
			k := EdgeIdentity(e)
			if i, dup := byEdge[k]; dup {
				// **안정 필드가 전부 같을 때만** 같은 엣지다. 그때는 횟수를 합치고 시각을 넓힌다.
				// 하나라도 다르면 다른 관측이라 둘 다 남는다 — 협상 그룹이 다른 두 연결은 두 사실이다.
				mergeEdge(edges[i], e)
				continue
			}
			byEdge[k] = len(edges)
			edges = append(edges, proto.Clone(e).(*discoveryv1.ObservedEdge))
		}
		comp = mergeCompleteness(comp, res.GetCompleteness())
	}
	if len(conflicts) > 0 {
		comp = mergeCompleteness(comp, &commonv1.Completeness{Note: strings.Join(conflicts, "; ")})
	}
	sortFindings(findings)
	sortEdges(edges)

	// 자산 스코프 게이트 — 노드 게이트(§1.4)를 자산 단위로 넓힌 것. 사용자가 선언한
	// 관리 대상만 남기고, 뺀 수는 고지용으로 보존한다.
	kept, excluded := policy.Apply(findings)

	snap := &history.Snapshot{
		ID:              snapshotID,
		NodeID:          nodeID,
		Findings:        kept,
		Edges:           edges,
		Completeness:    comp,
		RulesetVersion:  rulesetVersion,
		ExcludedByScope: excluded,
	}
	if store != nil {
		if err := store.Append(snap); err != nil { // append-only(§1.2)
			return nil, err
		}
	}
	return snap, nil
}

// EdgeIdentity — 엣지 동일성(인벤토리 설계 §7.3.2). **안정 필드 전부**다: 방향·주소·포트·
// 프로토콜·역할·탐지 방법·협상 그룹·암호군·앱. 관측 횟수와 시각만 뺀다 — 그 둘은 같은
// 엣지를 다시 본 사실이지 다른 엣지가 아니다.
//
// 전에는 방향·프로토콜·협상 그룹뿐이었다. 그러면 암호군이나 앱이 다른 두 관측이 하나로
// 접혀 먼저 온 것만 남았고, 결과 순서가 바뀌면 남는 것이 바뀌었다. history의 지문도 이 키로
// 정렬하므로 두 자리가 같은 것을 「같은 엣지」로 본다.
func EdgeIdentity(e *discoveryv1.ObservedEdge) string {
	return strings.Join([]string{
		e.GetSrcNodeId(), e.GetDstNodeId(), e.GetDstAddr(), fmt.Sprint(e.GetPort()),
		e.GetProtocol().String(), e.GetRole().String(), e.GetDetectionMethod().String(),
		e.GetNegotiatedGroup(), e.GetCipher(), e.GetAppKey(), e.GetAppKeyKind(),
	}, "|")
}

// mergeEdge — 같은 엣지를 다시 본 것을 하나로. 횟수를 합치고 첫·마지막 시각을 넓힌다.
func mergeEdge(into, e *discoveryv1.ObservedEdge) {
	into.ObservedCount += e.GetObservedCount()
	if f := e.GetFirstSeen(); f != nil && (into.GetFirstSeen() == nil || f.AsTime().Before(into.GetFirstSeen().AsTime())) {
		into.FirstSeen = f
	}
	if l := e.GetLastSeen(); l != nil && (into.GetLastSeen() == nil || l.AsTime().After(into.GetLastSeen().AsTime())) {
		into.LastSeen = l
	}
}

// sortResults — 정규화 전에 결과를 (collected_at, collector_id, 정준 바이트)로 정렬한다. 같은 입력
// 집합이면 같은 순서다. 정렬하지 않으면 같은 finding이 다르게 왔을 때 무엇이 남는지가 파일
// 순서에 달린다.
func sortResults(in []*discoveryv1.CollectionResult) []*discoveryv1.CollectionResult {
	out := append([]*discoveryv1.CollectionResult(nil), in...)
	key := func(r *discoveryv1.CollectionResult) (int64, int32, string, []byte) {
		at := r.GetEnvelope().GetCollectedAt()
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(r)
		return at.GetSeconds(), at.GetNanos(), r.GetEnvelope().GetCollectorId(), b
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, ni, ci, bi := key(out[i])
		sj, nj, cj, bj := key(out[j])
		if si != sj {
			return si < sj
		}
		if ni != nj {
			return ni < nj
		}
		if ci != cj {
			return ci < cj
		}
		return bytes.Compare(bi, bj) < 0
	})
	return out
}

func sortFindings(fs []*discoveryv1.Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].GetId() < fs[j].GetId() })
}

func sortEdges(es []*discoveryv1.ObservedEdge) {
	sort.SliceStable(es, func(i, j int) bool { return EdgeIdentity(es[i]) < EdgeIdentity(es[j]) })
}

// mergeCompleteness — 여러 collector의 완전성을 합친다. covered는 합집합, missing은
// (a.missing ∪ b.missing) \ covered. 한 collector가 관측하지 못한 계층을 다른 collector가 커버하면 갭 아님.
func mergeCompleteness(a, b *commonv1.Completeness) *commonv1.Completeness {
	if a == nil {
		a = &commonv1.Completeness{}
	}
	if b == nil {
		return a
	}
	coveredSet := map[commonv1.CollectionLayer]bool{}
	for _, l := range a.GetLayersCovered() {
		coveredSet[l] = true
	}
	for _, l := range b.GetLayersCovered() {
		coveredSet[l] = true
	}
	missingSet := map[commonv1.CollectionLayer]bool{}
	for _, l := range append(a.GetLayersMissing(), b.GetLayersMissing()...) {
		if !coveredSet[l] {
			missingSet[l] = true
		}
	}
	// note는 **하나도 버리지 않는다.** 전에는 먼저 비지 않은 것을 남겨, 뒤에 온 수집기의
	// 갭 설명이 사라졌고 결과 순서에 따라 남는 note가 달라졌다. 정렬해 이으면 순서와 무관하다.
	notes := map[string]bool{}
	for _, n := range append(strings.Split(a.GetNote(), "; "), strings.Split(b.GetNote(), "; ")...) {
		if n = strings.TrimSpace(n); n != "" {
			notes[n] = true
		}
	}
	var joined []string
	for n := range notes {
		joined = append(joined, n)
	}
	sort.Strings(joined)
	return &commonv1.Completeness{
		LayersCovered: keys(coveredSet),
		LayersMissing: keys(missingSet),
		Note:          strings.Join(joined, "; "),
	}
}

// keys — map을 **정렬해** 꺼낸다. map 순서로 두면 같은 입력에서 계층 순서가 흔들려 스냅샷이
// 달라진다.
func keys(m map[commonv1.CollectionLayer]bool) []commonv1.CollectionLayer {
	out := make([]commonv1.CollectionLayer, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
