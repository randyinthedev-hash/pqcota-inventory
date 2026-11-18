// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package pgschema_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/pgschema"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/store"
)

// 인벤토리 단계가 맡는 표 열하나. 스키마 SQL에서 뽑은 것이 이것과 같아야 한다 — 표가 늘면 이 목록과
// 릴리스 노트(「-init-schema를 다시 돌려라」)를 함께 고친다.
var inventoryTables = []string{
	"pqcota_edge_attribution", "pqcota_endpoint", "pqcota_observations", "pqcota_profile",
	"pqcota_rejections", "pqcota_retention_events", "pqcota_snapshots",
	"pqcota_source_inputs", "pqcota_source_interpretations", "pqcota_source_maps", "pqcota_source_receipts",
}

func parts() []pgschema.Part {
	return []pgschema.Part{history.Schema(), inventory.MetaSchema(), store.Schema()}
}

func allTables() []pgschema.Table {
	var ts []pgschema.Table
	for _, p := range parts() {
		ts = append(ts, p.Tables...)
	}
	return ts
}

func TestPartsCoverInventoryTables(t *testing.T) {
	var got []string
	for _, tb := range allTables() {
		got = append(got, tb.Name)
		if len(tb.Columns) == 0 {
			t.Errorf("%s: no columns parsed", tb.Name)
		}
	}
	sortStrings(got)
	if !reflect.DeepEqual(got, inventoryTables) {
		t.Fatalf("tables\n got %v\nwant %v", got, inventoryTables)
	}
}

type env struct {
	admin  *pgxpool.Pool
	schema string
	dsn    string // search_path가 schema를 가리킨다
}

// 빈 스키마를 search_path로 가리켜 「빈 DB」를 만든다.
func newEnv(t *testing.T) *env {
	t.Helper()
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "pqcota_init_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	return &env{admin: admin, schema: schema, dsn: withParam(dsn, "search_path", schema)}
}

func withParam(dsn, k, v string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + k + "=" + v
}

func (e *env) tables(t *testing.T) []string {
	t.Helper()
	rows, err := e.admin.Query(context.Background(), `SELECT tablename FROM pg_tables WHERE schemaname=$1 ORDER BY tablename`, e.schema)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (e *env) pool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// role — 로그인 역할을 만들고 그 역할로 접속하는 DSN을 돌려준다. 끝나면 지운다.
func (e *env) role(t *testing.T, name string) string {
	t.Helper()
	ctx := context.Background()
	u, err := url.Parse(e.dsn)
	if err != nil || u.Scheme == "" {
		t.Skip("PQCOTA_TEST_DSN is not a URL — cannot derive a DSN for a second role")
	}
	role := e.schema + "_" + name
	pw := "pw" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := e.admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+pw+"'"); err != nil {
		t.Fatalf("cannot create a role (the test account needs CREATEROLE): %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		e.admin.Exec(c, "DROP OWNED BY "+role+" CASCADE")
		e.admin.Exec(c, "DROP ROLE "+role)
	})
	u.User = url.UserPassword(role, pw)
	return u.String()
}

// 빈 스키마에서 열하나를 만들고, 두 번째는 만드는 것 없이 성공한다.
func TestInitCreatesAllThenIsIdempotent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p := e.pool(t, e.dsn)
	rep, err := pgschema.Init(ctx, p, parts()...)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep.Created, inventoryTables) || len(rep.Existing) != 0 {
		t.Fatalf("first run: %+v", rep)
	}
	if got := e.tables(t); !reflect.DeepEqual(got, inventoryTables) {
		t.Fatalf("tables: %v", got)
	}
	lines := strings.Split(strings.TrimSpace(pgschema.FormatReport(rep)), "\n")
	if last := lines[len(lines)-1]; last != "schema ready: 11 created, 0 already present" {
		t.Fatalf("success line: %q", last)
	}
	rep, err = pgschema.Init(ctx, p, parts()...)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Created) != 0 || !reflect.DeepEqual(rep.Existing, inventoryTables) {
		t.Fatalf("second run: %+v", rep)
	}
	if got := e.tables(t); len(got) != len(inventoryTables) {
		t.Fatalf("second run changed the tables: %v", got)
	}
}

// 뒤쪽 부분(메타)에서 실패하면 앞쪽 부분이 만든 표도 남지 않는다. 고친 뒤 다시 돌리면 성공한다.
func TestInitFailureRollsBackThenRerunSucceeds(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// 같은 이름의 뷰가 있으면 CREATE TABLE IF NOT EXISTS는 건너뛰고, 다음 ALTER TABLE이 실패한다.
	if _, err := e.admin.Exec(ctx, "CREATE VIEW "+e.schema+".pqcota_profile AS SELECT 1 AS x"); err != nil {
		t.Fatal(err)
	}
	p := e.pool(t, e.dsn)
	rep, err := pgschema.Init(ctx, p, parts()...)
	if err == nil {
		t.Fatalf("want a failure, got %+v", rep)
	}
	if !errors.Is(err, pgschema.ErrRolledBack) {
		t.Fatalf("want ErrRolledBack, got %v", err)
	}
	if len(rep.Created)+len(rep.Existing) != 0 {
		t.Fatalf("a failed run reported tables: %+v", rep)
	}
	if got := e.tables(t); len(got) != 0 {
		t.Fatalf("a failed run left tables behind: %v", got)
	}
	if _, err := e.admin.Exec(ctx, "DROP VIEW "+e.schema+".pqcota_profile"); err != nil {
		t.Fatal(err)
	}
	rep, err = pgschema.Init(ctx, p, parts()...)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Created) != len(inventoryTables) {
		t.Fatalf("rerun: %+v", rep)
	}
}

// 표가 없거나 열이 없으면 ErrMissing이고 초기화를 안내한다.
func TestCheckMissingTableAndColumn(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p := e.pool(t, e.dsn)
	err := pgschema.Check(ctx, p, history.Schema().Tables, history.InitHint)
	if !errors.Is(err, pgschema.ErrMissing) || errors.Is(err, pgschema.ErrPermission) {
		t.Fatalf("empty schema: %v", err)
	}
	if !strings.Contains(err.Error(), "pqcota_snapshots") || !strings.Contains(err.Error(), "-init-schema") {
		t.Fatalf("message: %v", err)
	}
	if _, err := pgschema.Init(ctx, p, parts()...); err != nil {
		t.Fatal(err)
	}
	if err := pgschema.Check(ctx, p, allTables(), history.InitHint); err != nil {
		t.Fatalf("after init: %v", err)
	}
	// 판을 올렸는데 초기화를 안 한 설치: 열이 하나 모자란다.
	if _, err := e.admin.Exec(ctx, "ALTER TABLE "+e.schema+".pqcota_snapshots DROP COLUMN content_hash_v1"); err != nil {
		t.Fatal(err)
	}
	err = pgschema.Check(ctx, p, history.Schema().Tables, history.InitHint)
	if !errors.Is(err, history.ErrSchemaMissing) || !strings.Contains(err.Error(), "pqcota_snapshots.content_hash_v1") {
		t.Fatalf("missing column: %v", err)
	}
}

// 권한 문제는 ErrPermission이고 초기화를 권하지 않는다. 접속 실패는 둘 다 아니다.
func TestCheckPermissionAndConnectionAreNotMissing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := pgschema.Init(ctx, e.pool(t, e.dsn), parts()...); err != nil {
		t.Fatal(err)
	}
	reader := e.role(t, "r")
	rp := e.pool(t, reader)
	notInit := func(err error, what string) {
		t.Helper()
		if !errors.Is(err, pgschema.ErrPermission) || errors.Is(err, pgschema.ErrMissing) {
			t.Fatalf("%s: want ErrPermission, got %v", what, err)
		}
		if strings.Contains(err.Error(), "init-schema") {
			t.Fatalf("%s: a permission error suggested initializing: %v", what, err)
		}
	}
	// USAGE 없음: 표가 보이지 않지만 「없다」가 아니다.
	notInit(pgschema.Check(ctx, rp, allTables(), history.InitHint), "no USAGE")
	if _, err := e.admin.Exec(ctx, "GRANT USAGE ON SCHEMA "+e.schema+" TO "+e.schema+"_r"); err != nil {
		t.Fatal(err)
	}
	// SELECT 없음.
	err := pgschema.Check(ctx, rp, allTables(), history.InitHint)
	notInit(err, "no SELECT")
	if !strings.Contains(err.Error(), "SELECT on pqcota_snapshots") {
		t.Fatalf("message: %v", err)
	}
	if _, err := e.admin.Exec(ctx, "GRANT SELECT ON ALL TABLES IN SCHEMA "+e.schema+" TO "+e.schema+"_r"); err != nil {
		t.Fatal(err)
	}
	if err := pgschema.Check(ctx, rp, allTables(), history.InitHint); err != nil {
		t.Fatalf("with USAGE and SELECT: %v", err)
	}
	// 조회용 열기 셋 모두 읽기 권한만으로 열린다.
	if s, err := history.OpenPgStoreIn(ctx, reader, "acme"); err != nil {
		t.Fatal(err)
	} else {
		s.Close()
	}
	if s, err := inventory.OpenPgMetaStoreIn(ctx, reader, "acme"); err != nil {
		t.Fatal(err)
	} else {
		s.Close()
	}
	if s, err := store.OpenPgStoreIn(ctx, reader, "acme"); err != nil {
		t.Fatal(err)
	} else {
		s.Close()
	}
	// 인증 실패와 접속 실패는 그대로 돌아온다.
	u, _ := url.Parse(reader)
	u.User = url.UserPassword(e.schema+"_r", "wrong")
	for what, dsn := range map[string]string{"bad password": u.String(), "unreachable": withPort(t, reader, "1")} {
		err := pgschema.Check(ctx, e.pool(t, dsn), allTables(), history.InitHint)
		if err == nil || errors.Is(err, pgschema.ErrMissing) || errors.Is(err, pgschema.ErrPermission) {
			t.Fatalf("%s: want a plain error, got %v", what, err)
		}
	}
}

func withPort(t *testing.T, dsn, port string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = u.Hostname() + ":" + port
	q := u.Query()
	q.Set("connect_timeout", "2")
	u.RawQuery = q.Encode()
	return u.String()
}

// 초기화 뒤 DML 권한만 가진 계정이 PQCOTA_AUTO_DDL=0으로 쓰기 저장소를 연다.
// 자동 DDL을 켠 채로는 같은 계정이 열지 못한다(ALTER TABLE은 소유자만) — 그래서 0을 권한다.
func TestWriterWithDMLOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := pgschema.Init(ctx, e.pool(t, e.dsn), parts()...); err != nil {
		t.Fatal(err)
	}
	w := e.role(t, "w")
	role := e.schema + "_w"
	for _, q := range []string{
		"GRANT USAGE ON SCHEMA " + e.schema + " TO " + role,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + e.schema + " TO " + role,
		"GRANT USAGE ON ALL SEQUENCES IN SCHEMA " + e.schema + " TO " + role,
	} {
		if _, err := e.admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(history.AutoDDLEnv, "")
	if _, err := inventory.NewPgMetaStoreIn(ctx, w, "acme"); err == nil || !pgschema.IsPrivilegeError(err) {
		t.Fatalf("automatic DDL as a non-owner: want a privilege error, got %v", err)
	}
	t.Setenv(history.AutoDDLEnv, "0")
	m, err := inventory.NewPgMetaStoreIn(ctx, w, "acme")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.UpsertEndpoint(&inventoryv1.MachineEndpoint{NodeId: "web-01"}); err != nil {
		t.Fatal(err)
	}
	h, err := history.NewPgStoreIn(ctx, w, "acme")
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	s, err := store.NewPgStoreIn(ctx, w, "acme")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

// PQCOTA_AUTO_DDL을 설정하지 않은 쓰기 열기는 지금과 같이 표를 만든다. 0이면 만들지 않는다.
func TestAutoDDLSwitchOnWriters(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	t.Setenv(history.AutoDDLEnv, "0")
	if _, err := inventory.NewPgMetaStoreIn(ctx, e.dsn, "acme"); !errors.Is(err, history.ErrSchemaMissing) {
		t.Fatalf("AUTO_DDL=0 on an empty schema: %v", err)
	}
	if got := e.tables(t); len(got) != 0 {
		t.Fatalf("AUTO_DDL=0 created tables: %v", got)
	}
	t.Setenv(history.AutoDDLEnv, "")
	m, err := inventory.NewPgMetaStoreIn(ctx, e.dsn, "acme")
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	if got := e.tables(t); !reflect.DeepEqual(got, []string{"pqcota_endpoint", "pqcota_profile"}) {
		t.Fatalf("automatic DDL: %v", got)
	}
}

func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}
