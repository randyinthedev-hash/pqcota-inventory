// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package history_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 노드의 현재 스냅샷(pqcota-inventory#1). 내용이 A → B → A로 돌아오면 세 번째 A는 첫 A를 다시 쓰고(중복
// 억제), 지금 상태(Latest)는 마지막 관측이 가리킨 A다. 같은 시험을 메모리와 Postgres 양쪽에 돌린다.

type prunableStore interface {
	history.Store
	Prune(history.Policy, bool) (*history.PruneReport, error)
}

// snapOf — 버전만 다른 OpenSSL finding 하나로 내용을 가른다.
func snapOf(id, node, version string) *history.Snapshot {
	return &history.Snapshot{ID: id, NodeID: node, RulesetVersion: "r1", Findings: []*discoveryv1.Finding{{
		Id:            "f1",
		CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL,
		RuntimeAxes:   &discoveryv1.Finding_Openssl{Openssl: &discoveryv1.OpensslAxes{Lib: "libssl.so.3", Version: version}},
	}}}
}

// appendABA — A → B → A를 적재하고 A·B의 id를 돌려준다.
func appendABA(t *testing.T, st history.Store, node string) (string, string) {
	t.Helper()
	a := snapOf(node+"-A", node, "3.0.1")
	if err := st.Append(a); err != nil {
		t.Fatal(err)
	}
	b := snapOf(node+"-B", node, "3.0.2")
	if err := st.Append(b); err != nil {
		t.Fatal(err)
	}
	a2 := snapOf(node+"-A2", node, "3.0.1")
	if err := st.Append(a2); err != nil {
		t.Fatal(err)
	}
	if a2.Created || a2.ID != a.ID {
		t.Fatalf("third ingest: created=%v id=%q — the same content must reuse A (%q)", a2.Created, a2.ID, a.ID)
	}
	return a.ID, b.ID
}

func checkABA(t *testing.T, st history.Store, node, aID string) {
	t.Helper()
	snaps, err := st.Snapshots(node)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 {
		t.Errorf("snapshots = %d, want 2 (duplicate suppression)", len(snaps))
	}
	stats, err := st.ObservationStats(node)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range stats {
		n += s.Count
	}
	if n != 3 || stats[aID].Count != 2 {
		t.Errorf("observations = %d (A: %d), want 3 (A: 2)", n, stats[aID].Count)
	}
	cur, err := st.Latest(node)
	if err != nil {
		t.Fatal(err)
	}
	if cur == nil || cur.ID != aID {
		t.Fatalf("Latest = %v, want A (%s) — the last ingest was A", idOf(cur), aID)
	}
}

func idOf(s *history.Snapshot) string {
	if s == nil {
		return "<nil>"
	}
	return s.ID
}

// runABA — 중복 억제·현재 스냅샷·keep-last 1을 한 저장소에서.
func runABA(t *testing.T, st prunableStore, node string) {
	aID, bID := appendABA(t, st, node)
	checkABA(t, st, node, aID)

	// keep-last 1: seq가 가장 큰 B와 현재 A가 둘 다 남는다.
	if _, err := st.Prune(history.Policy{KeepLast: 1}, true); err != nil {
		t.Fatal(err)
	}
	snaps, _ := st.Snapshots(node)
	ids := map[string]bool{}
	for _, s := range snaps {
		ids[s.ID] = true
	}
	if !ids[aID] || !ids[bID] {
		t.Errorf("after keep-last 1: %v — the current snapshot A and the newest B must both remain", ids)
	}
	if cur, _ := st.Latest(node); cur == nil || cur.ID != aID {
		t.Errorf("after keep-last 1: Latest = %s, want A", idOf(cur))
	}
}

func TestCurrentSnapshotMem(t *testing.T) {
	runABA(t, history.NewMemStore(), "n1")
}

func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	return dsn
}

func uniqueNode(prefix string) string {
	return prefix + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func TestCurrentSnapshotPg(t *testing.T) {
	dsn := pgDSN(t)
	st, err := history.NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runABA(t, st, uniqueNode("host://aba-"))
}

// TestCurrentSnapshotWithoutObservations — 관측 기록에 기댈 수 없는 옛 이력(계획 §3.1).
func TestCurrentSnapshotWithoutObservations(t *testing.T) {
	dsn := pgDSN(t)
	ctx := context.Background()
	st, err := history.NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}

	// (a) 관측 기록이 하나도 없다 → seq가 가장 큰 스냅샷(B).
	node := uniqueNode("host://noobs-a-")
	_, bID := appendABA(t, st, node)
	exec(`DELETE FROM pqcota_observations WHERE org='default' AND node_id=$1`, node)
	if cur, _ := st.Latest(node); cur == nil || cur.ID != bID {
		t.Errorf("(a) no observations: Latest = %s, want the newest (B)", idOf(cur))
	}

	// (b) 가장 최근 관측 기록 뒤에 관측 기록 없이 만든 스냅샷 → 그 스냅샷.
	node = uniqueNode("host://noobs-b-")
	appendABA(t, st, node)
	exec(`INSERT INTO pqcota_snapshots(org,id,node_id,ruleset_ver,findings,created_at)
	      VALUES('default',$1,$2,'r1','[]',clock_timestamp())`, node+"-C", node)
	if cur, _ := st.Latest(node); cur == nil || cur.ID != node+"-C" {
		t.Errorf("(b) a snapshot written after the last observation: Latest = %s, want C", idOf(cur))
	}

	// (c) 가장 최근 관측 기록이 가리키는 스냅샷이 없다 → seq가 가장 큰 스냅샷(B).
	node = uniqueNode("host://noobs-c-")
	aID, bID := appendABA(t, st, node)
	exec(`DELETE FROM pqcota_snapshots WHERE org='default' AND node_id=$1 AND id=$2`, node, aID)
	if cur, _ := st.Latest(node); cur == nil || cur.ID != bID {
		t.Errorf("(c) the observed snapshot is gone: Latest = %s, want the newest (B)", idOf(cur))
	}
}

// TestCurrentSnapshotSurvivesConcurrentPrune — 적재와 정리가 겹쳐도 가장 최근 관측이 가리키는 스냅샷이 남는다.
func TestCurrentSnapshotSurvivesConcurrentPrune(t *testing.T) {
	dsn := pgDSN(t)
	ctx := context.Background()
	st, err := history.NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	node := uniqueNode("host://race-")
	appendABA(t, st, node)
	for round := 0; round < 20; round++ {
		var wg sync.WaitGroup
		errs := make(chan error, 3)
		wg.Add(3)
		go func() { defer wg.Done(); errs <- st.Append(snapOf(fmt.Sprintf("%s-A%d", node, round), node, "3.0.1")) }()
		go func() { defer wg.Done(); errs <- st.Append(snapOf(fmt.Sprintf("%s-B%d", node, round), node, "3.0.2")) }()
		go func() {
			defer wg.Done()
			_, err := st.Prune(history.Policy{KeepLast: 1}, true)
			errs <- err
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		var snapID string
		if err := db.QueryRow(ctx, `SELECT snapshot_id FROM pqcota_observations WHERE org='default' AND node_id=$1 ORDER BY seq DESC LIMIT 1`, node).Scan(&snapID); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM pqcota_snapshots WHERE org='default' AND node_id=$1 AND id=$2`, node, snapID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatalf("round %d: the last observation points at %s, which was pruned", round, snapID)
		}
		if cur, _ := st.Latest(node); cur == nil || cur.ID != snapID {
			t.Fatalf("round %d: Latest = %s, want the snapshot of the last observation (%s)", round, idOf(cur), snapID)
		}
	}
}

// TestLatestDuringIngestAndPrune — 조회 중에 새 상태가 적재되고 정리가 옛 현재 스냅샷을 지워도, 이력이 남은
// 노드의 Latest는 빈 결과를 내지 않고 그 시점의 온전한 스냅샷을 낸다(고르기와 읽기가 한 문이다).
func TestLatestDuringIngestAndPrune(t *testing.T) {
	dsn := pgDSN(t)
	ctx := context.Background()
	st, err := history.NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	node := uniqueNode("host://readrace-")
	if err := st.Append(snapOf(node+"-0", node, "3.0.0")); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	wg.Add(1)
	go func() { // 쓰기: 매번 새 내용을 적재하고 keep-last 1로 정리한다. 옛 현재 스냅샷이 계속 지워진다.
		defer wg.Done()
		defer close(stop)
		for i := 1; i <= 150; i++ {
			if err := st.Append(snapOf(fmt.Sprintf("%s-%d", node, i), node, fmt.Sprintf("3.0.%d", i))); err != nil {
				errs <- err
				return
			}
			if _, err := st.Prune(history.Policy{KeepLast: 1}, true); err != nil {
				errs <- err
				return
			}
		}
	}()
	var reads, empties int
	var mu sync.Mutex
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s, err := st.Latest(node)
				mu.Lock()
				reads++
				switch {
				case err != nil:
					errs <- err
				case s == nil:
					empties++
				case len(s.Findings) != 1 || s.Findings[0].GetOpenssl().GetVersion() == "":
					errs <- fmt.Errorf("Latest returned a partial snapshot %s", s.ID)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if empties > 0 {
		t.Fatalf("Latest returned no snapshot %d times in %d reads, though the node always had history", empties, reads)
	}
	t.Logf("%d reads, none empty", reads)
}
