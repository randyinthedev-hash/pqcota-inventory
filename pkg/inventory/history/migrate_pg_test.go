package history_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// v0.8 모양 — content_hash_v1이 **없는** 표. 그 판이 실제로 만들던 열 그대로다.
const v08Snapshots = `
CREATE TABLE pqcota_snapshots (
    seq               BIGSERIAL PRIMARY KEY,
    id                TEXT NOT NULL,
    node_id           TEXT NOT NULL,
    ruleset_ver       TEXT NOT NULL,
    findings          JSONB NOT NULL,
    completeness      JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    edges             JSONB,
    content_hash      TEXT,
    excluded_by_scope INT NOT NULL DEFAULT 0,
    org               TEXT NOT NULL DEFAULT 'default'
);`

// ★ TV-HISTORY-10 — 옛 행이 쌓인 DB를 v0.9 코드로 연다.
//
// D8의 완료 조건이다. 중복 억제 기준을 v1로 옮겼으므로, 옛 행(v1이 빈 행)을 재사용하지 않고
// 새 행을 만들어야 그 행부터 참조가 찾힌다. 옛 지문으로 계속 접으면 v1 열이 영원히 비고
// 다운스트림의 참조가 영원히 해결되지 않는다.
//
// **전용 스키마에서 돈다.** 공유 표의 모양을 흔들지 않으려는 것이고, 그래야 「v0.8 표에 v0.9가
// 열과 인덱스를 더한다」를 실제로 재현할 수 있다. PQCOTA_TEST_DSN이 있을 때만.
func TestPgUpgradeFromV08(t *testing.T) {
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	ctx := context.Background()
	schema := "mig" + strconv.FormatInt(time.Now().UnixNano(), 36)

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")

	// ── v0.8: 표를 그 판의 모양으로 세우고 행 하나를 넣는다 ──
	scoped := withSearchPath(t, dsn, schema)
	old, err := pgxpool.New(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(ctx, v08Snapshots); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := old.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name='pqcota_snapshots' AND column_name='content_hash_v1'", schema).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("v0.8 표에 content_hash_v1 이 있다 — 이 테스트가 재현하려는 상태가 아니다")
	}
	// 옛 행. 그 판의 중복 억제 지문(content_hash)만 들고 있다.
	legacy := &history.Snapshot{ID: "ingest-old:n1", NodeID: "n1", RulesetVersion: "pqcota-enrich/v2",
		Findings: []*discoveryv1.Finding{{Id: "f1", Algorithm: "X25519"}}}
	if _, err := old.Exec(ctx,
		`INSERT INTO pqcota_snapshots(org,id,node_id,ruleset_ver,findings,completeness,edges,content_hash,excluded_by_scope)
		 VALUES('default',$1,$2,$3,'[{"id":"f1","algorithm":"X25519"}]'::jsonb,NULL,NULL,$4,0)`,
		legacy.ID, legacy.NodeID, legacy.RulesetVersion, history.ContentHash(legacy)); err != nil {
		t.Fatal(err)
	}
	old.Close()

	// ── v0.9 코드로 연다: 열과 인덱스가 더해진다 ──
	st, err := history.NewPgStore(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	check, _ := pgxpool.New(ctx, scoped)
	defer check.Close()
	if err := check.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name='pqcota_snapshots' AND column_name='content_hash_v1'", schema).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("v0.9 가 content_hash_v1 열을 더하지 않았다")
	}
	if err := check.QueryRow(ctx, "SELECT count(*) FROM pg_indexes WHERE schemaname=$1 AND indexname='idx_pqcota_snap_ref'", schema).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("참조 인덱스가 없다")
	}
	// 옛 행은 **빈 채 보존**된다. 소급하지 않는다 — 어느 규칙으로 계산했는지 값이 말하지 못한다.
	var v1 *string
	if err := check.QueryRow(ctx, "SELECT content_hash_v1 FROM pqcota_snapshots WHERE id=$1", legacy.ID).Scan(&v1); err != nil {
		t.Fatal(err)
	}
	if v1 != nil && *v1 != "" {
		t.Errorf("옛 행의 v1 을 소급해 채웠다: %q", *v1)
	}

	// ── 첫 적재: 같은 상태여도 **새 행** ──
	first := &history.Snapshot{ID: "ingest-new1:n1", NodeID: "n1", RulesetVersion: "pqcota-enrich/v2",
		Findings: []*discoveryv1.Finding{{Id: "f1", Algorithm: "X25519"}}}
	if err := st.Append(first); err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.ID == legacy.ID {
		t.Fatal("v1 이 빈 옛 행을 재사용했다 — 그러면 참조가 영원히 찾히지 않는다")
	}

	// ── 두 번째 적재: 같은 입력이면 새 행을 만들지 않는다 ──
	second := &history.Snapshot{ID: "ingest-new2:n1", NodeID: "n1", RulesetVersion: "pqcota-enrich/v2",
		Findings: []*discoveryv1.Finding{{Id: "f1", Algorithm: "X25519"}}}
	if err := st.Append(second); err != nil {
		t.Fatal(err)
	}
	if second.Created || second.ID != first.ID {
		t.Fatalf("같은 상태가 접히지 않았다: created=%v id=%s", second.Created, second.ID)
	}

	// 그 행부터 참조가 찾힌다.
	hit, err := st.ByContentHashV1("n1", "pqcota-enrich/v2", history.ContentHashV1(first))
	if err != nil || hit == nil || hit.ID != first.ID {
		t.Fatalf("이행 뒤 참조를 찾지 못한다: %v %v", hit, err)
	}
}

// withSearchPath — 그 스키마만 보도록 DSN에 옵션을 붙인다.
func withSearchPath(t *testing.T, dsn, schema string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("options", fmt.Sprintf("-csearch_path=%s", schema))
	u.RawQuery = q.Encode()
	return u.String()
}
