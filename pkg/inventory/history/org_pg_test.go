// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package history_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// TestPgOrgsShareATableAndStillDoNotSeeEachOther — **격리의 진짜 시험은 여기다.**
//
// MemStore 쪽 같은 이름의 테스트는 객체가 달라서 통과한다 — 모양은 확인해도 격리를 증명하지
// 못한다. 두 조직이 **한 테이블**을 공유하면서도 서로를 못 보는지는 Postgres에서만 잴 수 있다.
//
// PQCOTA_TEST_DSN이 있을 때만 돈다. 스킵은 통과가 아니다.
func TestPgOrgsShareATableAndStillDoNotSeeEachOther(t *testing.T) {
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	ctx := context.Background()
	// 실행마다 유니크 조직(append-only라 삭제하지 않는다).
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	a, err := history.NewPgStoreIn(ctx, dsn, "org-a-"+stamp)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := history.NewPgStoreIn(ctx, dsn, "org-b-"+stamp)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// 두 조직이 **같은 node_id**를 쓴다 — 현장에서 예외가 아니라 기본값에 가까운 상황이다.
	const node = "web-01"
	snapID := "snap-" + stamp
	if err := a.Append(&history.Snapshot{ID: snapID, NodeID: node, RulesetVersion: "r1"}); err != nil {
		t.Fatal(err)
	}

	if nodes, err := b.Nodes(); err != nil || len(nodes) != 0 {
		t.Fatalf("Nodes() leaks nodes of another organization: %v %v", nodes, err)
	}
	if s, err := b.ByID(snapID); err != nil || s != nil {
		t.Fatalf("ByID opens someone else's snapshot from the id alone: %v %v", s, err)
	}
	if s, err := b.Latest(node); err != nil || s != nil {
		t.Fatalf("Latest returns someone else's history for the same node_id: %v %v", s, err)
	}
	if snaps, err := b.Snapshots(node); err != nil || len(snaps) != 0 {
		t.Fatalf("Snapshots merges in someone else's history: %v %v", snaps, err)
	}

	// 자기 것은 보인다 — 격리가 과해서 자기 데이터를 잃는 것도 결함이다.
	if s, err := a.Latest(node); err != nil || s == nil || s.ID != snapID {
		t.Fatalf("the own organization history is not visible: %v %v", s, err)
	}
}
