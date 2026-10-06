// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package inventory_test

import (
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
)

// cbomOpenSSL — libcrypto 하나짜리 최소 CycloneDX. 버전만 바꿔 "같은 자산의 변경"을 만든다
// (finding id = node|name|runtime|fork 해시라 버전이 달라도 id는 유지된다).
func cbomOpenSSL(version string, extra string) []byte {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"libcrypto","properties":[
        {"name":"pqcota:crypto_runtime","value":"openssl"},
        {"name":"pqcota:detection_method","value":"runtime-introspection"},
        {"name":"pqcota:openssl.fork","value":"OpenSSL"},
        {"name":"pqcota:openssl.version","value":"` + version + `"}]}` + extra + `]}`)
}

const extraLibssl = `,
      {"type":"cryptographic-asset","name":"libssl","properties":[
        {"name":"pqcota:crypto_runtime","value":"openssl"},
        {"name":"pqcota:detection_method","value":"runtime-introspection"},
        {"name":"pqcota:openssl.fork","value":"OpenSSL"},
        {"name":"pqcota:openssl.version","value":"3.5.0"}]}`

func snapOf(t *testing.T, store history.Store, id, version, extra string, edges []*discoveryv1.ObservedEdge) *history.Snapshot {
	t.Helper()
	res := &discoveryv1.CollectionResult{
		Envelope:      &commonv1.Envelope{TargetNodeId: "node-db"},
		CbomCyclonedx: cbomOpenSSL(version, extra),
		ObservedEdges: edges,
	}
	snap, err := normalize.Normalize([]*discoveryv1.CollectionResult{res}, id, "node-db", "rs-1", store, nil)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// 스냅샷은 변화 지점에만 쌓이고, 저장소가 seq·시각을 부여한다.
func TestRenderHistory(t *testing.T) {
	store := history.NewMemStore()
	snapOf(t, store, "snap-a", "3.0.20", "", nil)
	snapOf(t, store, "snap-b", "3.5.0", extraLibssl, nil)

	snaps, err := store.Snapshots("node-db")
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 {
		t.Fatalf("the content changed, so there must be 2 snapshots, got %d", len(snaps))
	}
	if snaps[0].Seq == 0 || snaps[0].CreatedAt.IsZero() {
		t.Error("the store must assign seq and CreatedAt on ingest")
	}
	if snaps[0].Seq >= snaps[1].Seq {
		t.Errorf("seq must increase monotonically: %d → %d", snaps[0].Seq, snaps[1].Seq)
	}

	stats, err := store.ObservationStats("node-db")
	if err != nil {
		t.Fatal(err)
	}
	out := inventory.RenderHistory("node-db", snaps, stats, nil)
	for _, want := range []string{"node-db", "2 change points", "snap-a", "snap-b", "rs-1", "obs"} {
		if !strings.Contains(out, want) {
			t.Errorf("the history view is missing %q:\n%s", want, out)
		}
	}
}

// 같은 상태를 다시 관측하면 스냅샷은 늘지 않고 관측 기록만 쌓인다("매번 봤다"는 증거는 보존).
func TestRepeatObservationDoesNotDuplicateSnapshot(t *testing.T) {
	store := history.NewMemStore()
	first := snapOf(t, store, "snap-a", "3.0.20", "", nil)
	again := snapOf(t, store, "snap-a2", "3.0.20", "", nil) // 내용 동일, id만 다름
	changed := snapOf(t, store, "snap-b", "3.5.0", "", nil) // 버전 변경 → 새 스냅샷

	if !first.Created {
		t.Error("the first ingest must create a snapshot")
	}
	if again.Created {
		t.Error("re-observing identical content must not create a snapshot")
	}
	if again.ID != first.ID {
		t.Errorf("a re-observation must point at the existing snapshot: %s != %s", again.ID, first.ID)
	}
	if !changed.Created {
		t.Error("changed content must create a new snapshot")
	}

	snaps, _ := store.Snapshots("node-db")
	if len(snaps) != 2 {
		t.Fatalf("there must be as many snapshots as changes (2), got %d", len(snaps))
	}
	stats, _ := store.ObservationStats("node-db")
	if got := stats[first.ID].Count; got != 2 {
		t.Errorf("the first state must have been observed twice, got %d", got)
	}
	if stats[first.ID].First.After(stats[first.ID].Last) {
		t.Error("the observation window must satisfy First <= Last")
	}
}

// 휘발 필드(관측 횟수·시각)만 다른 것은 "변화"가 아니다 — 포함하면 중복 억제가 무력해진다.
func TestVolatileEdgeFieldsAreNotChange(t *testing.T) {
	store := history.NewMemStore()
	mk := func(count uint64) []*discoveryv1.ObservedEdge {
		return []*discoveryv1.ObservedEdge{{
			SrcNodeId: "node-web", DstNodeId: "node-db", Port: 4433,
			Protocol:        discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS,
			NegotiatedGroup: "x25519", ObservedCount: count,
		}}
	}
	snapOf(t, store, "s1", "3.0.20", "", mk(3))
	second := snapOf(t, store, "s2", "3.0.20", "", mk(9999)) // 빈도만 다름
	if second.Created {
		t.Error("a difference only in observation frequency is not a change")
	}
	third := snapOf(t, store, "s3", "3.0.20", "", []*discoveryv1.ObservedEdge{{
		SrcNodeId: "node-web", DstNodeId: "node-db", Port: 4433,
		Protocol:        discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS,
		NegotiatedGroup: "X25519MLKEM768", // 협상 그룹이 바뀌면 실질 변화
	}})
	if !third.Created {
		t.Error("a changed negotiated group must count as a change")
	}
}

// ByID — 이력 상세·diff의 진입점. 없으면 (nil, nil).
func TestByID(t *testing.T) {
	store := history.NewMemStore()
	snapOf(t, store, "snap-a", "3.0.20", "", nil)

	got, err := store.ByID("snap-a")
	if err != nil || got == nil {
		t.Fatalf("snap-a must be found: %v %v", got, err)
	}
	if got.NodeID != "node-db" {
		t.Errorf("node mismatch: %s", got.NodeID)
	}
	missing, err := store.ByID("snap-none")
	if err != nil || missing != nil {
		t.Errorf("an unknown id must return (nil, nil): %v %v", missing, err)
	}
}

// 상세 뷰는 자산 + 그 스냅샷의 관측 엣지를 함께 편다(누적 뷰는 합계만 내므로 여기서만 펼침).
func TestRenderDetailShowsEdges(t *testing.T) {
	store := history.NewMemStore()
	edges := []*discoveryv1.ObservedEdge{{
		SrcNodeId: "node-web", DstNodeId: "node-db", Port: 4433,
		Protocol: discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS,
		// 고전 그룹 — 등급이 🔴로 분류되어야 한다.
		NegotiatedGroup: "x25519", Cipher: "TLS_AES_256_GCM_SHA384",
	}}
	snap := snapOf(t, store, "snap-a", "3.0.20", "", edges)

	out := inventory.RenderDetail(snap)
	for _, want := range []string{"libcrypto/OpenSSL 3.0.20", "1 observed edges", "node-web", "node-db:4433", "x25519"} {
		if !strings.Contains(out, want) {
			t.Errorf("the detail view is missing %q:\n%s", want, out)
		}
	}
}

// diff는 추가·변경을 관측 사실로만 서술한다. 버전이 바뀐 자산은 id가 같아 "변경"으로 잡힌다.
func TestRenderDiff(t *testing.T) {
	store := history.NewMemStore()
	a := snapOf(t, store, "snap-a", "3.0.20", "", nil)
	b := snapOf(t, store, "snap-b", "3.5.0", extraLibssl, nil)

	out := inventory.RenderDiff(a, b)
	for _, want := range []string{"changes", "changed", "3.0.20", "3.5.0", "added", "libssl"} {
		if !strings.Contains(out, want) {
			t.Errorf("the diff is missing %q:\n%s", want, out)
		}
	}
	// 판정은 하지 않는다 — 위험/조치 같은 단어가 새어들면 §2.1 무판단 위반.
	for _, forbidden := range []string{"risky", "vulnerable", "action required"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("the diff must pass no judgment, yet it contains %q:\n%s", forbidden, out)
		}
	}
}

// 같은 스냅샷끼리는 변화가 없다고 말해야 한다(빈 출력이 아니라 명시).
func TestRenderDiffNoChange(t *testing.T) {
	store := history.NewMemStore()
	a := snapOf(t, store, "snap-a", "3.0.20", "", nil)
	if out := inventory.RenderDiff(a, a); !strings.Contains(out, "no asset changes") {
		t.Errorf("a diff of identical snapshots must say there is no change:\n%s", out)
	}
}
