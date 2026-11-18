// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/pgschema"
)

// AutoDDLEnv — 이 환경변수가 "0"이면 저장소를 열 때 스키마를 만들지 않는다.
//
// 생성자가 말없이 `CREATE TABLE`을 도는 것은 혼자 쓸 때 편하다. 그런데 가리키는 곳이 어긋나면
// **에러 없이 빈 테이블이 새로 생기고 거기에 쓴다** — 데이터가 사라진 것처럼 보이고, 여러
// 조직을 담는 저장소라면 남의 자리에 쓴다. 스키마 배포를 의도적 행위로 만들어야 하는 배포는
// 이것을 끄고, 스키마는 마이그레이션으로 미리 올린다.
//
// 끈 상태에서 스키마가 없으면 [ErrSchemaMissing]으로 중단한다 — 알리지 않고 만들어 주지 않는다.
// 스키마는 `pqcota-inventory -init-schema`로 미리 올린다. 메타·프로비저닝 기록 저장소도 이 스위치를 따른다.
const AutoDDLEnv = "PQCOTA_AUTO_DDL"

// ErrSchemaMissing — 필요한 표나 열이 없다. [pgschema.ErrMissing]과 같은 값이다(errors.Is로 둘 다 맞는다).
// 권한이 없어서 못 보는 것은 이것이 아니라 [pgschema.ErrPermission]이다 — 초기화를 권하지 않는다.
var ErrSchemaMissing = pgschema.ErrMissing

// InitHint — 표·열이 없을 때 안내하는 명령.
const InitHint = "run `pqcota-inventory -init-schema` as the schema owner, or check search_path"

// autoDDL — 기본은 켬. 명시적으로 "0"일 때만 끈다.
func autoDDL() bool { return os.Getenv(AutoDDLEnv) != "0" }

// AutoDDL — 다른 저장소(메타·프로비저닝 기록)가 같은 스위치를 따르도록 내보낸다.
func AutoDDL() bool { return autoDDL() }

// Schema — 이력 저장소가 맡은 표 전부(스냅샷·관측·절단·거절·선언). 초기화와 확인이 같은 SQL을 쓴다.
func Schema() pgschema.Part {
	return pgschema.NewPart("history", schemaSQL+rejectionSchemaSQL+attributionSchemaSQL)
}

// ensureSchema — 스키마를 올리거나, 올리지 않기로 했으면 표·열이 모두 있는지 확인만 한다.
func ensureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if autoDDL() {
		_, err := pool.Exec(ctx, schemaSQL+rejectionSchemaSQL+attributionSchemaSQL)
		return err
	}
	return pgschema.Check(ctx, pool, Schema().Tables, AutoDDLEnv+"=0 turned automatic creation off — "+InitHint)
}

// checkSchema — DDL 없이 이 저장소의 표·열이 모두 있고 읽을 수 있는지 본다(OpenPgStoreIn).
func checkSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return pgschema.Check(ctx, pool, Schema().Tables, InitHint)
}
