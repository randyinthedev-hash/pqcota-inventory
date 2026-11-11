// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
)

// schemaSQL — 스냅샷 테이블과 따로 둔다. 처음부터 org가 있으므로 기본값을 두지 않는다 — 조직을 모르는
// INSERT는 NOT NULL 위반으로 터진다.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS pqcota_source_inputs (
    org         TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    raw         BYTEA NOT NULL,
    size        BIGINT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),  -- 처음 받은 때. 그 뒤의 수신은 pqcota_source_receipts
    PRIMARY KEY (org, sha256)
);

-- 매핑 설정 원문(A2). 결과는 원문 해시로 가리킨다(본문의 maps[].sha256). 같은 원문은 한 번만 둔다.
CREATE TABLE IF NOT EXISTS pqcota_source_maps (
    org         TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    raw         BYTEA NOT NULL,
    source      TEXT NOT NULL,   -- preset·user
    map_id      TEXT NOT NULL,
    revision    TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org, sha256)
);

-- 변환 결과(불변). 갱신·삭제하지 않는다. body는 저장할 때의 JSON 바이트 그대로이고 body_sha256으로 같은지 본다.
CREATE TABLE IF NOT EXISTS pqcota_source_interpretations (
    seq               BIGSERIAL PRIMARY KEY,
    org               TEXT NOT NULL,
    id                TEXT NOT NULL,
    input_sha256      TEXT NOT NULL,
    schema_version    TEXT NOT NULL,
    converter_version TEXT NOT NULL,
    spec_version      TEXT NOT NULL,
    rules             JSONB NOT NULL,
    counts            JSONB NOT NULL,
    producer          JSONB NOT NULL,
    body              BYTEA NOT NULL,
    body_sha256       TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org, id),
    FOREIGN KEY (org, input_sha256) REFERENCES pqcota_source_inputs(org, sha256)
);
-- A2에서 더한 열. 이 열이 없던 개발 중 테이블에도 붙는다(그 행은 설정 없이 변환한 것이라 빈 목록이 맞다).
ALTER TABLE pqcota_source_interpretations ADD COLUMN IF NOT EXISTS maps JSONB NOT NULL DEFAULT '[]'::jsonb;
CREATE INDEX IF NOT EXISTS idx_pqcota_srcint_org ON pqcota_source_interpretations(org, seq DESC);

-- 수신 기록 — 받을 때마다 1행. 같은 것을 다시 받아도 내용 행은 늘지 않고 여기만 는다.
CREATE TABLE IF NOT EXISTS pqcota_source_receipts (
    seq                BIGSERIAL PRIMARY KEY,
    org                TEXT NOT NULL,
    node_id            TEXT NOT NULL DEFAULT '',
    input_sha256       TEXT NOT NULL,
    interpretation_id  TEXT NOT NULL,
    new_input          BOOLEAN NOT NULL,
    new_interpretation BOOLEAN NOT NULL,
    received_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (org, interpretation_id) REFERENCES pqcota_source_interpretations(org, id)
);
CREATE INDEX IF NOT EXISTS idx_pqcota_srcrcpt_org ON pqcota_source_receipts(org, seq DESC);
`

// PgStore — Postgres 구현. 핸들이 조직에 묶이고, 모든 질의가 그 조건을 단다.
type PgStore struct {
	pool *pgxpool.Pool
	org  org.ID
}

// NewPgStoreIn — 스키마 자동 생성은 history와 같은 스위치(history.AutoDDLEnv)를 따른다.
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
// 조회가 빈 DB에 테이블을 만들면 안 되고, 읽기 권한만 있는 계정으로도 열려야 한다.
// 테이블이 없으면 history.ErrSchemaMissing.
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

// tables — 소스 근거 테이블 전부. 하나라도 없으면 스키마가 없는 것으로 본다.
var tables = []string{"pqcota_source_inputs", "pqcota_source_maps", "pqcota_source_interpretations", "pqcota_source_receipts"}

func checkSchema(ctx context.Context, pool *pgxpool.Pool) error {
	var missing []string
	for _, t := range tables {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, t).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", history.ErrSchemaMissing, strings.Join(missing, ", "))
	}
	return nil
}

func ensureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if os.Getenv(history.AutoDDLEnv) != "0" {
		_, err := pool.Exec(ctx, schemaSQL)
		return err
	}
	if err := checkSchema(ctx, pool); err != nil {
		return fmt.Errorf("%w — %s=0 turned automatic creation off, apply the schema first", err, history.AutoDDLEnv)
	}
	return nil
}

// Org — 이 핸들이 묶인 조직.
func (p *PgStore) Org() org.ID { return p.org }

func (p *PgStore) Close() { p.pool.Close() }

func (p *PgStore) Save(in Input, interp *sourceevidence.Interpretation) (Receipt, error) {
	pr, err := prepare(in, interp)
	if err != nil {
		return Receipt{}, err
	}
	rules, err := json.Marshal(pr.summary.Rules)
	if err != nil {
		return Receipt{}, err
	}
	counts, err := json.Marshal(pr.summary.Counts)
	if err != nil {
		return Receipt{}, err
	}
	producer, err := json.Marshal(pr.summary.Producer)
	if err != nil {
		return Receipt{}, err
	}
	mapRefs, err := json.Marshal(pr.summary.Maps)
	if err != nil {
		return Receipt{}, err
	}

	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback(ctx) // 커밋한 뒤에는 아무 일도 하지 않는다

	r := Receipt{NodeID: in.NodeID, InputSHA256: pr.inputSHA, InterpretationID: pr.summary.ID}
	tag, err := tx.Exec(ctx,
		`INSERT INTO pqcota_source_inputs(org,sha256,raw,size) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
		p.org, pr.inputSHA, in.Raw, len(in.Raw))
	if err != nil {
		return Receipt{}, err
	}
	r.NewInput = tag.RowsAffected() == 1
	for _, m := range pr.maps {
		if _, err := tx.Exec(ctx,
			`INSERT INTO pqcota_source_maps(org,sha256,raw,source,map_id,revision) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			p.org, m.ref.SHA256, m.raw, m.ref.Source, m.ref.ID, m.ref.Revision); err != nil {
			return Receipt{}, err
		}
	}

	tag, err = tx.Exec(ctx,
		`INSERT INTO pqcota_source_interpretations
		   (org,id,input_sha256,schema_version,converter_version,spec_version,rules,counts,producer,body,body_sha256,maps)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (org,id) DO NOTHING`,
		p.org, pr.summary.ID, pr.inputSHA, pr.summary.SchemaVersion, pr.summary.ConverterVersion,
		pr.summary.SpecVersion, rules, counts, producer, pr.body, pr.bodySHA, mapRefs)
	if err != nil {
		return Receipt{}, err
	}
	r.NewInterpretation = tag.RowsAffected() == 1
	if !r.NewInterpretation {
		var stored string
		if err := tx.QueryRow(ctx,
			`SELECT body_sha256 FROM pqcota_source_interpretations WHERE org=$1 AND id=$2`,
			p.org, pr.summary.ID).Scan(&stored); err != nil {
			return Receipt{}, err
		}
		if stored != pr.bodySHA {
			return Receipt{}, fmt.Errorf("%w: %s", ErrImmutable, pr.summary.ID)
		}
	}

	if err := tx.QueryRow(ctx,
		`INSERT INTO pqcota_source_receipts(org,node_id,input_sha256,interpretation_id,new_input,new_interpretation)
		 VALUES($1,$2,$3,$4,$5,$6) RETURNING seq, received_at`,
		p.org, in.NodeID, pr.inputSHA, pr.summary.ID, r.NewInput, r.NewInterpretation).Scan(&r.Seq, &r.ReceivedAt); err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Receipt{}, err
	}
	r.ReceivedAt = r.ReceivedAt.UTC()
	return r, nil
}

func (p *PgStore) Interpretations(limit int) ([]Summary, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	rows, err := p.pool.Query(context.Background(),
		`SELECT id,input_sha256,spec_version,schema_version,converter_version,rules,counts,producer,maps,created_at
		 FROM pqcota_source_interpretations WHERE org=$1 ORDER BY seq DESC LIMIT $2`, p.org, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Summary
	for rows.Next() {
		var s Summary
		var rules, counts, producer, maps []byte
		if err := rows.Scan(&s.ID, &s.InputSHA256, &s.SpecVersion, &s.SchemaVersion, &s.ConverterVersion,
			&rules, &counts, &producer, &maps, &s.CreatedAt); err != nil {
			return nil, err
		}
		if err := errors.Join(json.Unmarshal(rules, &s.Rules), json.Unmarshal(counts, &s.Counts),
			json.Unmarshal(producer, &s.Producer), json.Unmarshal(maps, &s.Maps)); err != nil {
			return nil, err
		}
		s.CreatedAt = s.CreatedAt.UTC()
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *PgStore) Interpretation(id string) (*sourceevidence.Interpretation, error) {
	var body []byte
	err := p.pool.QueryRow(context.Background(),
		`SELECT body FROM pqcota_source_interpretations WHERE org=$1 AND id=$2`, p.org, id).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeInterpretation(body)
}

func (p *PgStore) MapRaw(sha string) ([]byte, error) {
	var raw []byte
	err := p.pool.QueryRow(context.Background(),
		`SELECT raw FROM pqcota_source_maps WHERE org=$1 AND sha256=$2`, p.org, sha).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

func (p *PgStore) InputRaw(sha string) ([]byte, error) {
	var raw []byte
	err := p.pool.QueryRow(context.Background(),
		`SELECT raw FROM pqcota_source_inputs WHERE org=$1 AND sha256=$2`, p.org, sha).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

func (p *PgStore) Receipts(limit int) ([]Receipt, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	rows, err := p.pool.Query(context.Background(),
		`SELECT seq,node_id,input_sha256,interpretation_id,new_input,new_interpretation,received_at
		 FROM pqcota_source_receipts WHERE org=$1 ORDER BY seq DESC LIMIT $2`, p.org, limit)
	return scanReceipts(rows, err)
}

func (p *PgStore) ReceiptsOf(id string, limit int) ([]Receipt, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	rows, err := p.pool.Query(context.Background(),
		`SELECT seq,node_id,input_sha256,interpretation_id,new_input,new_interpretation,received_at
		 FROM pqcota_source_receipts WHERE org=$1 AND interpretation_id=$2 ORDER BY seq DESC LIMIT $3`, p.org, id, limit)
	return scanReceipts(rows, err)
}

func scanReceipts(rows pgx.Rows, err error) ([]Receipt, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Receipt
	for rows.Next() {
		var r Receipt
		if err := rows.Scan(&r.Seq, &r.NodeID, &r.InputSHA256, &r.InterpretationID,
			&r.NewInput, &r.NewInterpretation, &r.ReceivedAt); err != nil {
			return nil, err
		}
		r.ReceivedAt = r.ReceivedAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}
