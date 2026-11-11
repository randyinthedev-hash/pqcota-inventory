// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package history_test

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// 조회용 연결(OpenPgStoreIn)은 빈 DB에 테이블을 만들지 않는다. 빈 스키마를 search_path로 가리켜 「빈 DB」를 만든다.
func TestPgOpenDoesNotCreateSchema(t *testing.T) {
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "pqcota_hro_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	scoped := dsn + sep + "search_path=" + schema
	tables := func() int {
		var n int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname=$1`, schema).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := history.OpenPgStoreIn(ctx, scoped, "acme"); !errors.Is(err, history.ErrSchemaMissing) {
		t.Fatalf("want ErrSchemaMissing, got %v", err)
	}
	if n := tables(); n != 0 {
		t.Fatalf("the read-only open created %d tables", n)
	}
	w, err := history.NewPgStoreIn(ctx, scoped, "acme")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	r, err := history.OpenPgStoreIn(ctx, scoped, "acme")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if s, err := r.ByID("nope"); err != nil || s != nil {
		t.Fatalf("%v %v", s, err)
	}
}
