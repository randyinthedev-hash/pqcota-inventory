package history_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// TV-HISTORY-9 — Postgres에서 중복 억제가 v1로 접히고, (node, ruleset, digest)로 찾힌다.
// PQCOTA_TEST_DSN이 있을 때만. CI가 Postgres 서비스로 돌린다.
func TestPgDedupAndLookupOnV1(t *testing.T) {
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	ctx := context.Background()
	st, err := history.NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var _ history.SnapshotLookup = st

	// append-only라 정리하지 않는다. 실행마다 유일한 노드로 다른 실행과 섞이지 않게 한다.
	node := "v1test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	mk := func(id, ruleset, alg string) *history.Snapshot {
		return &history.Snapshot{ID: id, NodeID: node, RulesetVersion: ruleset,
			Findings: []*discoveryv1.Finding{{Id: "f1", Algorithm: alg}}}
	}

	a := mk(node+"-1", "pqcota-enrich/v2", "X25519")
	if err := st.Append(a); err != nil {
		t.Fatal(err)
	}
	b := mk(node+"-2", "pqcota-enrich/v2", "X25519")
	_ = st.Append(b)
	if b.Created || b.ID != a.ID {
		t.Fatal("같은 상태가 접히지 않았다")
	}
	// 같은 내용, 다른 규칙 판 — 새 행.
	c := mk(node+"-3", "pqcota-enrich/v3", "X25519")
	_ = st.Append(c)
	if !c.Created {
		t.Fatal("규칙 판이 다른데 접혔다")
	}

	digest := history.ContentHashV1(a)
	got, err := st.ByContentHashV1(node, "pqcota-enrich/v2", digest)
	if err != nil || got == nil || got.ID != a.ID {
		t.Fatalf("찾지 못했다: %v %v", got, err)
	}
	if got, _ := st.ByContentHashV1(node, "pqcota-enrich/v3", digest); got != nil {
		t.Error("규칙 판이 다른데 찾았다 — 지문에 규칙 판이 들어 있으니 값도 달라야 한다")
	}
}
