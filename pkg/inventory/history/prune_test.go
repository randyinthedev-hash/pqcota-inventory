// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package history_test

import (
	"errors"
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// seed — 서로 다른 내용의 스냅샷 n건(= 변화 지점 n개)을 age[i] 전에 만든 것으로 넣는다.
func seed(t *testing.T, st *history.MemStore, node string, ages []time.Duration) []*history.Snapshot {
	t.Helper()
	now := time.Now().UTC()
	var out []*history.Snapshot
	for i, age := range ages {
		s := &history.Snapshot{
			ID: node + "-s" + string(rune('a'+i)), NodeID: node, RulesetVersion: "r1",
			CreatedAt: now.Add(-age),
			Findings: []*discoveryv1.Finding{{
				Id: "f1", CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL,
				// 버전을 달리해 매번 "변화"로 잡히게 한다.
				RuntimeAxes: &discoveryv1.Finding_Openssl{Openssl: &discoveryv1.OpensslAxes{
					Lib: "libssl.so.3", Version: "3.0." + string(rune('0'+i))}},
			}},
		}
		if err := st.Append(s); err != nil {
			t.Fatal(err)
		}
		if !s.Created {
			t.Fatalf("different content must produce a new snapshot: %s", s.ID)
		}
		out = append(out, s)
	}
	return out
}

// 축을 하나도 안 주면 "최신만 남기고 전부 삭제"가 되어 위험 — 거부해야 한다.
func TestPruneRequiresPolicy(t *testing.T) {
	st := history.NewMemStore()
	seed(t, st, "n1", []time.Duration{72 * time.Hour, time.Hour})
	if _, err := st.Prune(history.Policy{}, true); !errors.Is(err, history.ErrNoPolicy) {
		t.Errorf("an empty policy must be ErrNoPolicy, got %v", err)
	}
}

// dry-run은 아무것도 지우지 않는다.
func TestPruneDryRun(t *testing.T) {
	st := history.NewMemStore()
	seed(t, st, "n1", []time.Duration{100 * 24 * time.Hour, 99 * 24 * time.Hour, time.Hour})

	rep, err := st.Prune(history.Policy{OlderThan: 90 * 24 * time.Hour}, false)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := rep.Total(); s != 2 {
		t.Errorf("pruning plan = %d, want 2", s)
	}
	if snaps, _ := st.Snapshots("n1"); len(snaps) != 3 {
		t.Errorf("dry-run actually deleted: %d left, want 3", len(snaps))
	}
	if ev, _ := st.RetentionEvents("n1"); len(ev) != 0 {
		t.Error("a dry-run must not leave a prune record")
	}
}

// 최신 스냅샷은 아무리 오래돼도 지우지 않는다(인벤토리 뷰·before 캡처의 근거).
func TestPruneNeverDeletesLatest(t *testing.T) {
	st := history.NewMemStore()
	snaps := seed(t, st, "n1", []time.Duration{400 * 24 * time.Hour, 300 * 24 * time.Hour})

	rep, err := st.Prune(history.Policy{OlderThan: 24 * time.Hour}, true)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := rep.Total(); s != 1 {
		t.Errorf("pruned = %d, want 1 (the latest one is kept)", s)
	}
	left, _ := st.Snapshots("n1")
	if len(left) != 1 || left[0].ID != snaps[1].ID {
		t.Errorf("the latest must remain: %+v", left)
	}
	if latest, _ := st.Latest("n1"); latest == nil {
		t.Error("if Latest disappears the inventory view breaks")
	}
}

// 두 축을 다 주면 보수적으로 — 최근 N개 안에 들면 오래돼도 보존한다.
func TestPruneConservativeWithBothAxes(t *testing.T) {
	st := history.NewMemStore()
	seed(t, st, "n1", []time.Duration{
		400 * 24 * time.Hour, 300 * 24 * time.Hour, 200 * 24 * time.Hour, 100 * 24 * time.Hour,
	})
	// 전부 90일보다 오래됐지만 keep-last=3이 최근 3개를 붙든다 → 가장 오래된 1건만 절단.
	rep, err := st.Prune(history.Policy{OlderThan: 90 * 24 * time.Hour, KeepLast: 3}, true)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := rep.Total(); s != 1 {
		t.Errorf("pruned = %d, want 1 (keep-last keeps the most recent 3)", s)
	}
	if left, _ := st.Snapshots("n1"); len(left) != 3 {
		t.Errorf("remaining = %d, want 3", len(left))
	}
}

// 절단하면 그 사실이 기록으로 남아야 한다 — 없으면 이력의 구멍이 "관측 안 함"과 구분되지 않는다.
func TestPruneRecordsEvent(t *testing.T) {
	st := history.NewMemStore()
	seed(t, st, "n1", []time.Duration{100 * 24 * time.Hour, 99 * 24 * time.Hour, time.Hour})

	if _, err := st.Prune(history.Policy{OlderThan: 90 * 24 * time.Hour}, true); err != nil {
		t.Fatal(err)
	}
	ev, _ := st.RetentionEvents("n1")
	if len(ev) != 1 {
		t.Fatalf("prune records = %d, want 1", len(ev))
	}
	if ev[0].Snapshots != 2 || ev[0].Observations != 2 {
		t.Errorf("record content mismatch: %+v", ev[0])
	}
	if ev[0].Policy == "" || ev[0].PrunedUpTo.IsZero() {
		t.Errorf("which policy cut how far must be recorded: %+v", ev[0])
	}
}
