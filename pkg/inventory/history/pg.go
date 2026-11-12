// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/org"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS pqcota_snapshots (
    seq          BIGSERIAL PRIMARY KEY,
    id           TEXT NOT NULL,
    node_id      TEXT NOT NULL,
    ruleset_ver  TEXT NOT NULL,
    findings     JSONB NOT NULL,
    completeness JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pqcota_snap_node ON pqcota_snapshots(node_id, seq);
-- 통신 엣지 레인(인벤토리 설계 §6). 기존 테이블에도 멱등 추가.
ALTER TABLE pqcota_snapshots ADD COLUMN IF NOT EXISTS edges JSONB;
-- 내용 지문 — 같은 상태의 반복 관측을 접기 위함. 기존 행은 NULL(지문 미상 → 항상 새로 만듦).
ALTER TABLE pqcota_snapshots ADD COLUMN IF NOT EXISTS content_hash TEXT;
-- 자산 스코프로 제외한 finding 수(제외 ≠ 부재 — 뷰가 고지해야 한다).
ALTER TABLE pqcota_snapshots ADD COLUMN IF NOT EXISTS excluded_by_scope INT NOT NULL DEFAULT 0;
-- 참조용 지문(규격 pqcota-snapshot-content/v1). 다운스트림이 같은 스냅샷을 같은 규칙으로 만들어
-- 같은 값을 내고, 이력이 이 값으로 찾는다. **접는 기준도 이것이다** — content_hash 는 보존하되
-- 키가 아니다. 옛 지문으로 접으면 v1 이 없는 옛 행이 재사용되어 v1 참조가 영원히 찾히지 않는다.
-- 기존 행은 NULL 이고 소급하지 않는다: 어느 규칙으로 계산했는지 값이 말하지 못한다.
ALTER TABLE pqcota_snapshots ADD COLUMN IF NOT EXISTS content_hash_v1 TEXT;

-- 관측 기록(가벼움) — 적재할 때마다 1행. 스냅샷은 변화 시에만 쌓이므로,
-- "언제·몇 번 관측했나"(관측 증명)는 이쪽이 보존한다.
CREATE TABLE IF NOT EXISTS pqcota_observations (
    seq         BIGSERIAL PRIMARY KEY,
    node_id     TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,  -- 이 관측이 확인한 상태
    ruleset_ver TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pqcota_obs_node ON pqcota_observations(node_id, seq);

-- 절단 기록 — 보존 정책으로 지운 사실. 없으면 이력의 구멍이 "관측을 안 함"과 구분되지 않는다.
CREATE TABLE IF NOT EXISTS pqcota_retention_events (
    seq          BIGSERIAL PRIMARY KEY,
    node_id      TEXT NOT NULL,
    pruned_upto  TIMESTAMPTZ NOT NULL,
    snapshots    INT NOT NULL,
    observations INT NOT NULL,
    policy       TEXT NOT NULL,
    executed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pqcota_ret_node ON pqcota_retention_events(node_id, seq);

-- 조직 축(v0.2.0). 기본값을 두는 이유는 **기존 행을 채우기 위해서다** — 옛 데이터가 어느 조직
-- 것인지 기계는 모르므로 org.Default로 넣고, 그 사실이 값으로 남는다.
-- 여러 조직을 한 저장소에 담는 배포는 이행 후 기본값을 뗀다(docs/compatibility.md §5):
--   ALTER TABLE <t> ALTER COLUMN org DROP DEFAULT;
-- 그러면 조직을 모르는 옛 바이너리의 INSERT가 NOT NULL 위반으로 터진다 — 조용한 오염 대신
-- 시끄러운 실패다.
ALTER TABLE pqcota_snapshots        ADD COLUMN IF NOT EXISTS org TEXT NOT NULL DEFAULT 'default';
ALTER TABLE pqcota_observations     ADD COLUMN IF NOT EXISTS org TEXT NOT NULL DEFAULT 'default';
ALTER TABLE pqcota_retention_events ADD COLUMN IF NOT EXISTS org TEXT NOT NULL DEFAULT 'default';
-- 인덱스 선두가 org다. 조직이 하나뿐인 저장소에서도 손해가 없고(선두 컬럼이 상수), 여럿이면
-- 조직 안에서만 훑는다. 옛 인덱스는 지우지 않는다 — 지우는 것은 되돌릴 수 없다.
CREATE INDEX IF NOT EXISTS idx_pqcota_snap_org ON pqcota_snapshots(org, node_id, seq);
-- 참조 조회 (org, node, ruleset, v1 지문). org 열이 위에서 생긴 뒤에 만들어야 한다 — 새 DB 에서
-- 이 줄이 org 보다 앞에 있으면 "column org does not exist" 로 스키마 전체가 멈춘다(CI 에서 그랬다).
CREATE INDEX IF NOT EXISTS idx_pqcota_snap_ref ON pqcota_snapshots(org, node_id, ruleset_ver, content_hash_v1);
CREATE INDEX IF NOT EXISTS idx_pqcota_obs_org  ON pqcota_observations(org, node_id, seq);
CREATE INDEX IF NOT EXISTS idx_pqcota_ret_org  ON pqcota_retention_events(org, node_id, seq);
`

// PgStore — Postgres append-only 히스토리(§2.4⑥ 영속화, §1.2 원본 불변).
// INSERT만 한다 — 스냅샷은 절대 갱신/삭제하지 않는다. 파생 Finding은 protojson으로 보존.
//
// **핸들이 조직에 묶인다.** 모든 질의가 그 조건을 달고 나가고, 빼는 방법이 없다 — 질의마다
// 기억할 일이 없으니 잊을 일도 없다.
type PgStore struct {
	pool *pgxpool.Pool
	org  org.ID
}

// NewPgStore — 조직을 대지 않고 연다. org.Default에 묶인다.
//
// 시그니처를 바꾸지 않는다(docs/compatibility.md §3). 여러 조직을 담는 배포는
// PQCOTA_REQUIRE_ORG=1로 이 경로를 막고 NewPgStoreIn을 쓴다.
func NewPgStore(ctx context.Context, dsn string) (*PgStore, error) {
	return NewPgStoreIn(ctx, dsn, "")
}

// NewPgStoreIn — 조직에 묶인 저장소를 연다. organization이 빈 문자열이면 org.Resolve의 규칙을
// 따른다(기본 조직, 단 필수 모드에서는 에러).
func NewPgStoreIn(ctx context.Context, dsn, organization string) (*PgStore, error) {
	o, err := org.Resolve(organization)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := ensureSchema(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &PgStore{pool: pool, org: o}, nil
}

// OpenPgStoreIn — 조회용으로 연다. DDL을 돌리지 않고 테이블이 있는지만 본다(PQCOTA_AUTO_DDL과 무관).
// 승인처럼 읽기만 하는 자리가 빈 DB에 테이블을 만들면 안 되고, 읽기 권한만 있는 계정으로도 열려야 한다.
// 테이블이 없으면 ErrSchemaMissing. 쓰기 메서드를 부르면 권한에 따라 실패한다 — 조회에만 쓴다.
func OpenPgStoreIn(ctx context.Context, dsn, organization string) (*PgStore, error) {
	o, err := org.Resolve(organization)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := checkSchema(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &PgStore{pool: pool, org: o}, nil
}

// Org — 이 핸들이 묶인 조직.
func (p *PgStore) Org() org.ID { return p.org }

func (p *PgStore) Close() { p.pool.Close() }

func (p *PgStore) Append(s *Snapshot) error {
	fj, err := marshalFindings(s.Findings)
	if err != nil {
		return err
	}
	var cj []byte
	if s.Completeness != nil {
		if cj, err = protojson.Marshal(s.Completeness); err != nil {
			return err
		}
	}
	ej, err := marshalEdges(s.Edges)
	if err != nil {
		return err
	}
	ctx := context.Background()
	hash := ContentHash(s)
	hashV1 := ContentHashV1(s)

	// 노드마다 잠근다. 정리(Prune)가 「현재가 아니다」라고 보고 지우는 스냅샷을 이 적재가 동시에 다시
	// 쓰면, 관측 기록이 사라진 스냅샷을 가리키게 된다. 둘 다 같은 잠금 안에서 읽고 쓴다.
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // 커밋한 뒤의 롤백은 아무 일도 하지 않는다
	if err := p.lockNode(ctx, tx, s.NodeID); err != nil {
		return err
	}

	// 실질 내용이 이력의 어느 스냅샷과 같으면 스냅샷을 새로 만들지 않는다 — 관측 기록만 남긴다.
	// 중간에 변했다 되돌아온 경우(A → B → A)도 그 최신 동일본을 가리킨다. 지금 상태는 관측 기록이
	// 정한다([PgStore.Latest]).
	var prevID string
	var prevSeq int64
	var prevAt time.Time
	err = tx.QueryRow(ctx,
		`SELECT id, seq, created_at FROM pqcota_snapshots
		 WHERE org=$1 AND node_id=$2 AND ruleset_ver=$3 AND content_hash_v1=$4 ORDER BY seq DESC LIMIT 1`,
		p.org, s.NodeID, s.RulesetVersion, hashV1).Scan(&prevID, &prevSeq, &prevAt)
	switch {
	case err == nil:
		s.ID, s.Seq, s.CreatedAt, s.Created = prevID, prevSeq, prevAt, false
		if err := p.observe(ctx, tx, s.NodeID, prevID, s.RulesetVersion); err != nil {
			return err
		}
		return tx.Commit(ctx)
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}

	// seq·created_at은 DB가 부여한다 — RETURNING으로 되받아 호출자의 스냅샷에 채운다.
	if err := tx.QueryRow(ctx,
		`INSERT INTO pqcota_snapshots(org,id,node_id,ruleset_ver,findings,completeness,edges,content_hash,excluded_by_scope,content_hash_v1,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp()) RETURNING seq, created_at`,
		p.org, s.ID, s.NodeID, s.RulesetVersion, fj, cj, ej, hash, s.ExcludedByScope, hashV1).Scan(&s.Seq, &s.CreatedAt); err != nil {
		return err
	}
	s.Created = true
	if err := p.observe(ctx, tx, s.NodeID, s.ID, s.RulesetVersion); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// pgq — 풀과 트랜잭션이 함께 갖는 조회. 같은 질의를 잠금 안팎에서 쓴다.
type pgq interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// lockNode — (조직, 노드)마다의 트랜잭션 잠금. 커밋·롤백 때 풀린다. 키는 두 해시다. 서로 다른 노드의
// 해시가 겹치면 그 둘이 한 줄로 설 뿐이고(느려질 뿐), 틀린 결과가 나오지는 않는다.
func (p *PgStore) lockNode(ctx context.Context, tx pgx.Tx, nodeID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, string(p.org), nodeID)
	return err
}

// observe — 관측 기록 한 행. 시각은 잠금을 잡은 뒤의 실제 시각(clock_timestamp)이다. 트랜잭션 시작
// 시각(now())을 쓰면, 잠금을 늦게 잡은 적재의 시각이 먼저 끝난 적재보다 앞서 [PgStore.currentSeq]의
// 시각 비교가 뒤집힌다. 스냅샷의 created_at도 같은 까닭으로 clock_timestamp다.
func (p *PgStore) observe(ctx context.Context, q pgq, nodeID, snapID, ruleset string) error {
	_, err := q.Exec(ctx,
		`INSERT INTO pqcota_observations(org,node_id,snapshot_id,ruleset_ver,observed_at) VALUES($1,$2,$3,$4,clock_timestamp())`,
		p.org, nodeID, snapID, ruleset)
	return err
}

// currentSeq — 노드의 현재 스냅샷의 seq([Store.Latest]의 약속). 스냅샷이 없으면 ok=false.
//
//   - 관측 기록이 없다 → seq가 가장 큰 스냅샷
//   - 가장 최근 관측 기록보다 나중에 만든 스냅샷이 있다(관측 기록 없이 쓴 옛 적재) → seq가 가장 큰 스냅샷
//   - 가장 최근 관측 기록이 가리키는 스냅샷이 없다 → seq가 가장 큰 스냅샷
//   - 그 밖 → 가장 최근 관측 기록이 가리키는 스냅샷
func (p *PgStore) currentSeq(ctx context.Context, q pgq, nodeID string) (int64, bool, error) {
	var newest int64
	var newestAt time.Time
	err := q.QueryRow(ctx,
		`SELECT seq, created_at FROM pqcota_snapshots WHERE org=$1 AND node_id=$2 ORDER BY seq DESC LIMIT 1`,
		p.org, nodeID).Scan(&newest, &newestAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var obsSnap string
	var obsAt time.Time
	err = q.QueryRow(ctx,
		`SELECT snapshot_id, observed_at FROM pqcota_observations WHERE org=$1 AND node_id=$2 ORDER BY seq DESC LIMIT 1`,
		p.org, nodeID).Scan(&obsSnap, &obsAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return newest, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	if newestAt.After(obsAt) {
		return newest, true, nil
	}
	var cur int64
	err = q.QueryRow(ctx,
		`SELECT seq FROM pqcota_snapshots WHERE org=$1 AND node_id=$2 AND id=$3 ORDER BY seq DESC LIMIT 1`,
		p.org, nodeID, obsSnap).Scan(&cur)
	if errors.Is(err, pgx.ErrNoRows) {
		return newest, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	return cur, true, nil
}

// ObservationStats — 노드의 스냅샷별 관측 요약(횟수·첫·마지막).
func (p *PgStore) ObservationStats(nodeID string) (map[string]ObsStat, error) {
	rows, err := p.pool.Query(context.Background(),
		`SELECT snapshot_id, count(*), min(observed_at), max(observed_at)
		 FROM pqcota_observations WHERE org=$1 AND node_id=$2 GROUP BY snapshot_id`, p.org, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ObsStat{}
	for rows.Next() {
		var id string
		var st ObsStat
		if err := rows.Scan(&id, &st.Count, &st.First, &st.Last); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

// snapCols — 스캔 순서는 scanSnapshot과 반드시 일치해야 한다.
const snapCols = `seq,id,node_id,ruleset_ver,findings,completeness,edges,created_at,excluded_by_scope`

// Latest — 노드의 현재 스냅샷([Store.Latest]의 약속, [PgStore.currentSeq]).
func (p *PgStore) Latest(nodeID string) (*Snapshot, error) {
	ctx := context.Background()
	seq, ok, err := p.currentSeq(ctx, p.pool, nodeID)
	if err != nil || !ok {
		return nil, err
	}
	row := p.pool.QueryRow(ctx,
		`SELECT `+snapCols+` FROM pqcota_snapshots WHERE org=$1 AND seq=$2`, p.org, seq)
	return scanSnapshot(row)
}

// ByID — 스냅샷 id 단건. id에 유일 제약이 없으므로 같은 id가 여러 번 적재됐다면 최신 것을 준다.
func (p *PgStore) ByID(id string) (*Snapshot, error) {
	row := p.pool.QueryRow(context.Background(),
		`SELECT `+snapCols+` FROM pqcota_snapshots
		 WHERE org=$1 AND id=$2 ORDER BY seq DESC LIMIT 1`, p.org, id)
	return scanSnapshot(row)
}

func (p *PgStore) ByContentHashV1(node, ruleset, digest string) (*Snapshot, error) {
	if digest == "" {
		return nil, nil
	}
	row := p.pool.QueryRow(context.Background(),
		`SELECT `+snapCols+` FROM pqcota_snapshots
		 WHERE org=$1 AND node_id=$2 AND ruleset_ver=$3 AND content_hash_v1=$4 ORDER BY seq DESC LIMIT 1`,
		p.org, node, ruleset, digest)
	return scanSnapshot(row)
}

func (p *PgStore) Nodes() ([]string, error) {
	rows, err := p.pool.Query(context.Background(),
		`SELECT DISTINCT node_id FROM pqcota_snapshots WHERE org=$1 ORDER BY node_id`, p.org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (p *PgStore) Snapshots(nodeID string) ([]*Snapshot, error) {
	return p.snapshots(context.Background(), p.pool, nodeID)
}

func (p *PgStore) snapshots(ctx context.Context, q pgq, nodeID string) ([]*Snapshot, error) {
	rows, err := q.Query(ctx,
		`SELECT `+snapCols+` FROM pqcota_snapshots
		 WHERE org=$1 AND node_id=$2 ORDER BY seq ASC`, p.org, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Snapshot
	for rows.Next() {
		s, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

type scannable interface {
	Scan(dest ...any) error
}

func scanSnapshot(r scannable) (*Snapshot, error) {
	var s Snapshot
	var fj, cj, ej []byte
	if err := r.Scan(&s.Seq, &s.ID, &s.NodeID, &s.RulesetVersion, &fj, &cj, &ej, &s.CreatedAt, &s.ExcludedByScope); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // Latest 대상 없음
		}
		return nil, err
	}
	fs, err := unmarshalFindings(fj)
	if err != nil {
		return nil, err
	}
	s.Findings = fs
	if len(cj) > 0 {
		c := &commonv1.Completeness{}
		if err := protojson.Unmarshal(cj, c); err != nil {
			return nil, err
		}
		s.Completeness = c
	}
	es, err := unmarshalEdges(ej)
	if err != nil {
		return nil, err
	}
	s.Edges = es
	return &s, nil
}

func marshalFindings(fs []*discoveryv1.Finding) ([]byte, error) {
	arr := make([]json.RawMessage, 0, len(fs))
	for _, f := range fs {
		b, err := protojson.Marshal(f)
		if err != nil {
			return nil, err
		}
		arr = append(arr, b)
	}
	return json.Marshal(arr)
}

func unmarshalFindings(b []byte) ([]*discoveryv1.Finding, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, err
	}
	out := make([]*discoveryv1.Finding, 0, len(arr))
	for _, raw := range arr {
		f := &discoveryv1.Finding{}
		if err := protojson.Unmarshal(raw, f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func marshalEdges(es []*discoveryv1.ObservedEdge) ([]byte, error) {
	if len(es) == 0 {
		return nil, nil
	}
	arr := make([]json.RawMessage, 0, len(es))
	for _, e := range es {
		b, err := protojson.Marshal(e)
		if err != nil {
			return nil, err
		}
		arr = append(arr, b)
	}
	return json.Marshal(arr)
}

func unmarshalEdges(b []byte) ([]*discoveryv1.ObservedEdge, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, err
	}
	out := make([]*discoveryv1.ObservedEdge, 0, len(arr))
	for _, raw := range arr {
		e := &discoveryv1.ObservedEdge{}
		if err := protojson.Unmarshal(raw, e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
