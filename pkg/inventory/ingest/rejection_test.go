// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"errors"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/scope"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/ingest"
)

func res(node string) *discoveryv1.CollectionResult {
	return &discoveryv1.CollectionResult{Envelope: &commonv1.Envelope{
		CollectorId: "openssl-collector", TargetNodeId: node,
	}}
}

func opts(store history.Store) ingest.IngestOptions {
	return ingest.IngestOptions{SnapshotPrefix: "snap", RulesetVersion: "r1", Store: store}
}

// TestRequiredModeRefusesToIngestWithoutAVerifier — 검증자가 없으면 **적재 자체가 시작되지 않는다.**
//
// 결과를 하나씩 거절하는 것이 아니라 여는 자리에서 막는다 — 알리지 않고 통과하는 경로가 열려 있는지가
// 문제이지, 어떤 결과가 왔는지는 문제가 아니기 때문이다.
func TestRequiredModeRefusesToIngestWithoutAVerifier(t *testing.T) {
	o := opts(history.NewMemStore())
	o.RequireSignature = true
	if _, err := ingest.IngestWith([]*discoveryv1.CollectionResult{res("web-01")}, o); !errors.Is(err, ingest.ErrSignatureRequired) {
		t.Fatalf("required mode, yet it ingested without a verifier: %v", err)
	}

	// 검증자가 있으면 통과한다.
	o.VerifySig = func(*discoveryv1.CollectionResult) bool { return true }
	if _, err := ingest.IngestWith([]*discoveryv1.CollectionResult{res("web-01")}, o); err != nil {
		t.Fatalf("a verifier was present, yet it was blocked: %v", err)
	}
}

// TestUnverifiedIsNotTheSameAsPassed — "검증했고 통과했다"와 "검증할 키가 없었다"를 가른다.
//
// 이 둘을 한 숫자로 합치면 리포트가 실제보다 강한 말을 하게 된다 — 이 리포가 완전성 맵으로
// 갈라 온 것과 같은 구분이다.
func TestUnverifiedIsNotTheSameAsPassed(t *testing.T) {
	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{res("web-01")}, opts(history.NewMemStore()))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unverified != 1 {
		t.Errorf("unverified count is %d — must be 1", rep.Unverified)
	}
	if rep.Rejected != 0 {
		t.Errorf("counted as a verification failure (%d) — it did not fail, it was never checked", rep.Rejected)
	}
	if rep.Accepted != 1 {
		t.Errorf("it was not ingested (%d) — unchecked is not rejected", rep.Accepted)
	}
}

// TestRejectionsOutliveTheProcess — 받지 않은 사실이 저장소에 남는다.
//
// 남기지 않으면 "러너가 잘못 설정돼 계속 거절당하고 있었다"와 "그 노드에서는 아무 일도 없었다"가
// 구분되지 않는다. 절단 기록이 이력의 구멍을 구분해 주는 것과 같은 자리다.
func TestRejectionsOutliveTheProcess(t *testing.T) {
	store := history.NewMemStore()
	o := opts(store)
	o.Rejections = store
	o.Master = scope.NewMaster([]string{"web-01"}) // db-99는 미등재
	o.VerifySig = func(r *discoveryv1.CollectionResult) bool {
		return r.GetEnvelope().GetTargetNodeId() != "web-02"
	}

	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{
		res("web-01"), // 통과
		res("db-99"),  // 미등재 → off-scope
		res(""),       // 앵커 없음 → off-scope
	}, o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OffScope != 2 {
		t.Fatalf("%d off-scope — must be 2", rep.OffScope)
	}

	got, err := store.Rejections(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d rejection records — must be 2: %+v", len(got), got)
	}
	for _, r := range got {
		if r.Kind != history.RejectOffScope {
			t.Errorf("kind is %q", r.Kind)
		}
		if r.Reason == "" {
			t.Error("the reason is empty — a record without a why cannot be read")
		}
		if r.CollectorID == "" {
			t.Error("the collector was not recorded — you cannot tell which runner is misconfigured")
		}
		if r.CanonicalHash == "" {
			t.Error("there is no fingerprint — you cannot count whether the same thing keeps arriving")
		}
		if r.At.IsZero() {
			t.Error("there is no timestamp")
		}
	}
}

// TestRejectionStoreIsOptional — 남길 곳을 안 주면 v0.1.x와 똑같이 돈다.
func TestRejectionStoreIsOptional(t *testing.T) {
	o := opts(history.NewMemStore())
	o.Master = scope.NewMaster([]string{"web-01"})
	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{res("db-99")}, o)
	if err != nil || rep.OffScope != 1 {
		t.Fatalf("ingest behaved differently when there was nowhere to record: %+v %v", rep, err)
	}
}
