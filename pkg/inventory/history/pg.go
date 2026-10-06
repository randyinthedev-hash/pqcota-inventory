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

	// 실질 내용이 직전과 같으면 스냅샷을 새로 만들지 않는다 — 관측 기록만 남긴다.
	var prevID string
	var prevSeq int64
	var prevAt time.Time
	err = p.pool.QueryRow(ctx,
		`SELECT id, seq, created_at FROM pqcota_snapshots
		 WHERE org=$1 AND node_id=$2 AND ruleset_ver=$3 AND content_hash_v1=$4 ORDER BY seq DESC LIMIT 1`,
		p.org, s.NodeID, s.RulesetVersion, hashV1).Scan(&prevID, &prevSeq, &prevAt)
	switch {
	case err == nil:
		// 직전 스냅샷과 같은 내용인지 확인 — 중간에 변했다 되돌아온 경우도 그 최신 동일본을 가리킨다.
		s.ID, s.Seq, s.CreatedAt, s.Created = prevID, prevSeq, prevAt, false
		return p.observe(ctx, s.NodeID, prevID, s.RulesetVersion)
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}

	// seq·created_at은 DB가 부여한다 — RETURNING으로 되받아 호출자의 스냅샷에 채운다.
	if err := p.pool.QueryRow(ctx,
		`INSERT INTO pqcota_snapshots(org,id,node_id,ruleset_ver,findings,completeness,edges,content_hash,excluded_by_scope,content_hash_v1)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING seq, created_at`,
		p.org, s.ID, s.NodeID, s.RulesetVersion, fj, cj, ej, hash, s.ExcludedByScope, hashV1).Scan(&s.Seq, &s.CreatedAt); err != nil {
		return err
	}
	s.Created = true
	return p.observe(ctx, s.NodeID, s.ID, s.RulesetVersion)
}

func (p *PgStore) observe(ctx context.Context, nodeID, snapID, ruleset string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO pqcota_observations(org,node_id,snapshot_id,ruleset_ver) VALUES($1,$2,$3,$4)`,
		p.org, nodeID, snapID, ruleset)
	return err
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

func (p *PgStore) Latest(nodeID string) (*Snapshot, error) {
	row := p.pool.QueryRow(context.Background(),
		`SELECT `+snapCols+` FROM pqcota_snapshots
		 WHERE org=$1 AND node_id=$2 ORDER BY seq DESC LIMIT 1`, p.org, nodeID)
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
	rows, err := p.pool.Query(context.Background(),
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
