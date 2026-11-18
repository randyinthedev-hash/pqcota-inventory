// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"errors"

	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/pgschema"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
)

const metaSchemaSQL = `
CREATE TABLE IF NOT EXISTS pqcota_endpoint (
    node_id    TEXT PRIMARY KEY,
    endpoint   JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pqcota_profile (
    node_id    TEXT PRIMARY KEY,
    profile    JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 조직 축(v0.2.0). 기존 행은 org.Default로 채워진다. 여러 조직을 담는 배포는 이행 후
-- 기본값을 뗀다(docs/compatibility.md §5).
ALTER TABLE pqcota_endpoint ADD COLUMN IF NOT EXISTS org TEXT NOT NULL DEFAULT 'default';
ALTER TABLE pqcota_profile  ADD COLUMN IF NOT EXISTS org TEXT NOT NULL DEFAULT 'default';

-- PK를 (org, node_id)로 옮긴다. **이 리포에서 유일하게 멱등하지 않은 이행이다** —
-- ADD PRIMARY KEY에는 IF NOT EXISTS가 없다. 그래서 지금 PK가 한 컬럼인지 보고 그때만 돈다.
-- 이걸 안 하면 아래 ON CONFLICT(org,node_id)가 옛 DB에서 런타임에 터진다.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['pqcota_endpoint','pqcota_profile'] LOOP
    IF EXISTS (
      SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
      WHERE c.relname = t AND i.indisprimary AND i.indnatts = 1
    ) THEN
      EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', t, t || '_pkey');
      EXECUTE format('ALTER TABLE %I ADD PRIMARY KEY (org, node_id)', t);
    END IF;
  END LOOP;
END $$;
`

// PgMetaStore — Postgres 머신 메타데이터. node_id PK로 **upsert**한다(사용자 재사용·수정 가능·인벤토리 설계 §2.0).
// 히스토리(append-only)와 다르다. 접근 비밀은 스키마에 없다 — MachineEndpoint 자체가 비밀 필드가 없다.
//
// **핸들이 조직에 묶인다** — PgStore와 같은 규칙이다.
type PgMetaStore struct {
	pool *pgxpool.Pool
	org  org.ID
}

// NewPgMetaStore — 조직을 대지 않고 연다(org.Default). 시그니처를 바꾸지 않는다.
func NewPgMetaStore(ctx context.Context, dsn string) (*PgMetaStore, error) {
	return NewPgMetaStoreIn(ctx, dsn, "")
}

// NewPgMetaStoreIn — 조직에 묶인 메타 저장소.
func NewPgMetaStoreIn(ctx context.Context, dsn, organization string) (*PgMetaStore, error) {
	o, err := org.Resolve(organization)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := ensureMetaSchema(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &PgMetaStore{pool: pool, org: o}, nil
}

// OpenPgMetaStoreIn — 조회용으로 연다. DDL을 돌리지 않고 표·열이 있고 읽을 수 있는지만 본다(PQCOTA_AUTO_DDL과 무관).
// 조회가 빈 DB에 표를 만들면 안 되고, 읽기 권한만 있는 계정으로도 열려야 한다.
// 표·열이 없으면 history.ErrSchemaMissing, 권한이 없으면 pgschema.ErrPermission. 쓰기 메서드는 권한에 따라 실패한다.
func OpenPgMetaStoreIn(ctx context.Context, dsn, organization string) (*PgMetaStore, error) {
	o, err := org.Resolve(organization)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pgschema.Check(ctx, pool, MetaSchema().Tables, history.InitHint); err != nil {
		pool.Close()
		return nil, err
	}
	return &PgMetaStore{pool: pool, org: o}, nil
}

// MetaSchema — 메타 저장소의 표 둘(엔드포인트·프로필). 초기화와 확인이 같은 SQL을 쓴다.
func MetaSchema() pgschema.Part { return pgschema.NewPart("metadata", metaSchemaSQL) }

// ensureMetaSchema — 이력과 같은 스위치(PQCOTA_AUTO_DDL)를 따른다. v0.15.0까지는 스위치와 상관없이 늘 DDL을 돌렸다.
// 그래서 표의 소유자가 아닌 계정은 DML 권한이 있어도 이 저장소를 열지 못했다(ALTER TABLE은 소유자만).
func ensureMetaSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if history.AutoDDL() {
		_, err := pool.Exec(ctx, metaSchemaSQL)
		return err
	}
	return pgschema.Check(ctx, pool, MetaSchema().Tables, history.AutoDDLEnv+"=0 turned automatic creation off — "+history.InitHint)
}

// Org — 이 핸들이 묶인 조직(org.Scoped).
func (p *PgMetaStore) Org() org.ID { return p.org }

func (p *PgMetaStore) Close() { p.pool.Close() }

func (p *PgMetaStore) UpsertEndpoint(e *inventoryv1.MachineEndpoint) error {
	j, err := protojson.Marshal(e)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(context.Background(),
		`INSERT INTO pqcota_endpoint(org,node_id,endpoint,updated_at) VALUES($1,$2,$3,now())
		 ON CONFLICT(org,node_id) DO UPDATE SET endpoint=$3, updated_at=now()`, p.org, e.GetNodeId(), j)
	return err
}

func (p *PgMetaStore) UpsertProfile(pr *inventoryv1.MachineProfile) error {
	j, err := protojson.Marshal(pr)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(context.Background(),
		`INSERT INTO pqcota_profile(org,node_id,profile,updated_at) VALUES($1,$2,$3,now())
		 ON CONFLICT(org,node_id) DO UPDATE SET profile=$3, updated_at=now()`, p.org, pr.GetNodeId(), j)
	return err
}

func (p *PgMetaStore) Endpoint(nodeID string) (*inventoryv1.MachineEndpoint, error) {
	var j []byte
	err := p.pool.QueryRow(context.Background(),
		`SELECT endpoint FROM pqcota_endpoint WHERE org=$1 AND node_id=$2`, p.org, nodeID).Scan(&j)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e := &inventoryv1.MachineEndpoint{}
	return e, protojson.Unmarshal(j, e)
}

func (p *PgMetaStore) Profile(nodeID string) (*inventoryv1.MachineProfile, error) {
	var j []byte
	err := p.pool.QueryRow(context.Background(),
		`SELECT profile FROM pqcota_profile WHERE org=$1 AND node_id=$2`, p.org, nodeID).Scan(&j)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pr := &inventoryv1.MachineProfile{}
	return pr, protojson.Unmarshal(j, pr)
}
