// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package normalize_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 노드별 병합은 입력 순서에 기대지 않는다. 결과 파일이 어떤 순서로 오든 같은 스냅샷이 나와야
// 다른 자리(다운스트림)가 같은 결과 집합으로 같은 지문을 낸다. 전에는 같은 finding·같은 엣지·
// 완전성 note 모두 「먼저 온 것이 우선한다」였다.

// result — 한 수집기의 결과. version이 다르면 같은 finding id에 다른 내용이 된다.
func result(collector, version string, at int64, edges ...*discoveryv1.ObservedEdge) *discoveryv1.CollectionResult {
	cbom := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"libcrypto","properties":[
        {"name":"pqcota:crypto_runtime","value":"openssl"},
        {"name":"pqcota:openssl.version","value":%q},
        {"name":"pqcota:openssl.fork","value":"OpenSSL"}]}]}`, version)
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			TargetNodeId: "n1", CollectorId: collector, CollectedAt: timestamppb.New(timeAt(at)),
			DetectionMethod: commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
		},
		CbomCyclonedx: []byte(cbom), CyclonedxSpecVersion: "1.6",
		ObservedEdges: edges,
		Completeness: &commonv1.Completeness{
			LayersCovered: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS},
			Note:          "note from " + collector,
		},
	}
}

func timeAt(s int64) time.Time { return time.Unix(1700000000+s, 0).UTC() }

func edge(group, cipher string, count uint64) *discoveryv1.ObservedEdge {
	return &discoveryv1.ObservedEdge{SrcNodeId: "n1", DstNodeId: "db", Port: 5432,
		Protocol: discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS, NegotiatedGroup: group, Cipher: cipher, ObservedCount: count}
}

// ★ TK-PIPELINE-3 — 결과 순서를 섞어도 같은 스냅샷이다.
func TestNormalizeIsOrderInvariant(t *testing.T) {
	mk := func() []*discoveryv1.CollectionResult {
		return []*discoveryv1.CollectionResult{
			result("openssl-collector", "3.0.2", 100, edge("x25519", "A", 1)),
			result("network-collector", "3.0.2", 200, edge("x25519", "A", 2), edge("x25519", "B", 1)),
			result("jvm-collector", "3.0.2", 150),
		}
	}
	want, err := normalize.Normalize(mk(), "s", "n1", normalize.RulesetVersion, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantV1 := history.ContentHashV1(want)
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 10; i++ {
		rs := mk()
		r.Shuffle(len(rs), func(a, b int) { rs[a], rs[b] = rs[b], rs[a] })
		got, err := normalize.Normalize(rs, "s", "n1", normalize.RulesetVersion, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if history.ContentHashV1(got) != wantV1 {
			t.Fatalf("순서를 섞었더니 스냅샷이 달라졌다 (%d번째)", i)
		}
	}
}

// TK-PIPELINE-3 — 같은 finding을 두 수집기가 다르게 보면, 최근 것을 남기되 알리지 않고 고르지 않는다.
// 「최근」은 수집 시각이지 수집기 이름순이 아니다.
func TestConflictingFindingKeepsTheLatestAndSaysSo(t *testing.T) {
	// 이름순으로는 a가 앞이지만 시각은 b가 앞이다 — 최근은 a다.
	rs := []*discoveryv1.CollectionResult{
		result("b-collector", "3.0.2", 100),
		result("a-collector", "3.5.0", 200),
	}
	snap, err := normalize.Normalize(rs, "s", "n1", normalize.RulesetVersion, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Findings) != 1 {
		t.Fatalf("finding %d", len(snap.Findings))
	}
	if v := snap.Findings[0].GetOpenssl().GetVersion(); v != "3.5.0" {
		t.Errorf("최근 수집(3.5.0)이 아니라 %s 가 남았다", v)
	}
	if !strings.Contains(snap.Completeness.GetNote(), "differs between collectors") {
		t.Errorf("두 수집기가 다르게 봤다는 사실이 note 에 없다: %q", snap.Completeness.GetNote())
	}
	// 같은 내용이면 알리지 않는다 — 늘 뜨는 알림은 읽히지 않는다.
	same, _ := normalize.Normalize([]*discoveryv1.CollectionResult{result("a", "3.0.2", 1), result("b", "3.0.2", 2)}, "s", "n1", normalize.RulesetVersion, nil, nil)
	if strings.Contains(same.Completeness.GetNote(), "differs") {
		t.Error("같은 내용인데 다르다고 알렸다")
	}
}

// TK-PIPELINE-3 — 엣지는 안정 필드 전부가 같을 때만 같은 엣지다. 그때 횟수를 합친다. 암호군만
// 달라도 다른 관측이라 둘 다 남는다. 전에는 방향·프로토콜·협상 그룹만 봐서 뒤의 것이 사라졌다.
func TestEdgeIdentityIsEveryStableField(t *testing.T) {
	rs := []*discoveryv1.CollectionResult{
		result("net-1", "3.0.2", 1, edge("x25519", "A", 3)),
		result("net-2", "3.0.2", 2, edge("x25519", "A", 4), edge("x25519", "B", 1)),
	}
	snap, err := normalize.Normalize(rs, "s", "n1", normalize.RulesetVersion, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Edges) != 2 {
		t.Fatalf("암호군이 다른 두 엣지가 %d개로 접혔다", len(snap.Edges))
	}
	for _, e := range snap.Edges {
		if e.GetCipher() == "A" && e.GetObservedCount() != 7 {
			t.Errorf("같은 엣지의 횟수가 합쳐지지 않았다: %d", e.GetObservedCount())
		}
	}
}

// TK-PIPELINE-3 — 완전성 note는 하나도 버리지 않고, 계층은 정렬돼 나온다.
func TestCompletenessMergeKeepsEveryNote(t *testing.T) {
	rs := []*discoveryv1.CollectionResult{result("b", "3.0.2", 1), result("a", "3.0.2", 2)}
	snap, _ := normalize.Normalize(rs, "s", "n1", normalize.RulesetVersion, nil, nil)
	note := snap.Completeness.GetNote()
	if !strings.Contains(note, "note from a") || !strings.Contains(note, "note from b") {
		t.Errorf("note 가 사라졌다: %q", note)
	}
	if strings.Index(note, "note from a") > strings.Index(note, "note from b") {
		t.Errorf("note 가 정렬되지 않았다: %q", note)
	}
}
