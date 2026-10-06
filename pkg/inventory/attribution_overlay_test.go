// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package inventory_test

import (
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/declaration"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/ingest"
)

// declaredInto — CSV를 적재 경로로 넣는다. 선언은 스냅샷이 아니라 선언 저장소로 간다.
func declaredInto(t *testing.T, store *history.MemStore, csv string) {
	t.Helper()
	res, err := declaration.ImportAttributionCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := ingest.IngestWith(res, ingest.IngestOptions{
		SnapshotPrefix: "d", RulesetVersion: "r1", Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.DeclaredAttributions == 0 {
		t.Fatal("the declaration did not land in the declaration store")
	}
	if rep.Snapshots != 0 {
		t.Fatalf("the declaration created %d snapshots — it must not take a place in the node's state history", rep.Snapshots)
	}
}

func observed(t *testing.T) *history.Snapshot {
	t.Helper()
	return &history.Snapshot{
		ID: "s1", NodeID: "web-01",
		Completeness: &commonv1.Completeness{Note: "1 of 2 edges could not be attributed to an app"},
		Edges: []*discoveryv1.ObservedEdge{
			// 관측이 이미 잡은 것
			{SrcNodeId: "web-01", DstAddr: "10.0.0.5", Port: 443, AppKey: "payment.service", AppKeyKind: "systemd-unit"},
			// 못 잡은 것 — 선언이 메울 자리
			{SrcNodeId: "web-01", DstAddr: "10.0.0.7", Port: 22},
		},
	}
}

// TestDeclarationNeverOverwritesObservation — **이 릴리스에서 가장 중요한 규칙이다.**
//
// 덮어쓰게 두면 사람이 적은 것과 기계가 본 것이 섞이고, 선언 레인을 따로 둔 이유가 사라진다.
func TestDeclarationNeverOverwritesObservation(t *testing.T) {
	// 관측이 이미 채운 자리를 노리는 선언을 일부러 넣는다.
	store := history.NewMemStore()
	declaredInto(t, store, "node_id,dst,app_key\nweb-01,10.0.0.5,another-app-written-by-a-person\nweb-01,10.0.0.7,batch-job.service\n")
	out := inventory.RenderDetailWith(observed(t), inventory.BuildAttributionOverlay(store))

	if strings.Contains(out, "another-app-written-by-a-person") {
		t.Error("the declaration overwrote an observation")
	}
	if !strings.Contains(out, "@payment.service") {
		t.Error("the app that observation attributed has vanished")
	}
	if !strings.Contains(out, "@batch-job.service(declared)") {
		t.Error("the blank was not filled by the declaration — or it was, without the declared marker")
	}
	// 화면만 보면 관측과 구별되지 않으므로 몇 개가 선언인지 밝힌다.
	if !strings.Contains(out, "1 of them are not observations") {
		t.Error("it does not say how many were filled by declarations")
	}
}

// TestOverlayDoesNotMutateTheStoredEdge — 저장된 관측은 읽어도 그대로다.
//
// 적재가 관측을 고치면 collector의 서명과 어긋나고, raw_capture에서 다시 계산할 때 저장된 값과
// 갈린다. 그래서 합치는 일은 **읽을 때만** 일어나야 한다.
func TestOverlayDoesNotMutateTheStoredEdge(t *testing.T) {
	snap := observed(t)
	store := history.NewMemStore()
	declaredInto(t, store, "web-01,10.0.0.7,batch-job.service\n")
	_ = inventory.RenderDetailWith(snap, inventory.BuildAttributionOverlay(store))

	if got := snap.Edges[1].GetAppKey(); got != "" {
		t.Fatalf("the stored edge changed to %q — that field is covered by the signature", got)
	}
	if got := snap.Edges[1].GetAppKeyKind(); got != "" {
		t.Fatalf("the stored edge's kind changed to %q", got)
	}
}

// TestDeclarationNeverEntersTheTimeline — **선언을 스냅샷 밖에 두는 설계의 핵심이다.**
//
// 선언이 노드의 스냅샷 타임라인에 들어가면 조회·이력·diff가 저마다 그것을 걸러 내야 하고,
// 화면이 늘 때마다 같은 자리가 다시 샌다. 실제로 기본 조회와 이력에서 두 번 샜다.
func TestDeclarationNeverEntersTheTimeline(t *testing.T) {
	store := history.NewMemStore()
	declaredInto(t, store, "web-01,10.0.0.7,batch-job.service\n") // 스냅샷 0을 안에서 검사한다
	if nodes, _ := store.Nodes(); len(nodes) != 0 {
		t.Fatalf("the declaration created a node: %v", nodes)
	}
	got, err := store.Attributions()
	if err != nil || len(got) != 1 {
		t.Fatalf("it never reached the declaration store: %v %v", got, err)
	}
}

// TestRedeclaringOverwrites — 선언은 사람이 고치는 것이라 append-only가 아니다.
func TestRedeclaringOverwrites(t *testing.T) {
	store := history.NewMemStore()
	declaredInto(t, store, "web-01,10.0.0.7,first.service\n")
	declaredInto(t, store, "web-01,10.0.0.7,second.service\n")
	got, _ := store.Attributions()
	if len(got) != 1 || got[0].AppKey != "second.service" {
		t.Fatalf("declaring again did not overwrite: %+v", got)
	}
}

// TestAttributionCSVRefusesWhatItCannotPlace — 어느 엣지를 가리키는지 모르는 줄은 받지 않는다.
func TestAttributionCSVRefusesWhatItCannotPlace(t *testing.T) {
	for _, bad := range []string{
		"web-01,10.0.0.7,\n", // 어느 앱인지가 없다
		",10.0.0.7,app\n",    // 어느 노드인지 모른다
		"web-01,,app\n",      // 어느 엣지인지 모른다
	} {
		if _, err := declaration.ImportAttributionCSV(strings.NewReader(bad)); err == nil {
			t.Errorf("a row that must be refused was accepted: %q", strings.TrimSpace(bad))
		}
	}
}
