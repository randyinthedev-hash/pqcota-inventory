// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 시험 실행 파일이 자기 자신을 이 명령으로 다시 띄운다. 종료 코드와 출력을 그대로 잰다.
func TestMain(m *testing.M) {
	if os.Getenv("PQCOTA_INVENTORY_TEST_MAIN") == "1" {
		os.Args = append([]string{"pqcota-inventory"}, strings.Fields(os.Getenv("PQCOTA_INVENTORY_TEST_ARGS"))...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runInventory(t *testing.T, dsn string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"PQCOTA_INVENTORY_TEST_MAIN=1",
		"PQCOTA_INVENTORY_TEST_ARGS="+strings.Join(args, " "),
		"PQCOTA_DSN="+dsn,
		"PQCOTA_ORG=acme",
		"PQCOTA_AUTO_DDL=",
	)
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), o.String(), e.String()
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, o.String(), e.String()
}

// -init-schema는 DSN이 없거나 조회 옵션·인자와 함께 오면 접속하기 전에 종료 2로 거부한다.
// 닿지 않는 주소를 DSN으로 주어, 접속을 시도했다면 2가 아닌 다른 결과가 나오게 한다.
func TestInitSchemaRefusesOtherArguments(t *testing.T) {
	unreachable := "postgres://nobody@127.0.0.1:1/none?connect_timeout=1"
	for name, c := range map[string]struct {
		dsn  string
		args []string
	}{
		"no DSN":      {"", []string{"-init-schema"}},
		"-history":    {unreachable, []string{"-init-schema", "-history", "web-01"}},
		"-snapshot":   {unreachable, []string{"-init-schema", "-snapshot", "s1"}},
		"-diff":       {unreachable, []string{"-init-schema", "-diff", "a,b"}},
		"an argument": {unreachable, []string{"-init-schema", "extra"}},
	} {
		code, out, errOut := runInventory(t, c.dsn, c.args...)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2 (stderr %q)", name, code, errOut)
		}
		if strings.Contains(out, "schema ready") {
			t.Errorf("%s: printed a success line", name)
		}
	}
}

// 빈 DB에서 조회는 표를 만들지 않고 초기화를 안내하며 종료 1. -init-schema가 표를 만들고 성공 줄을 낸 뒤에는 조회가 된다.
func TestQueryOnEmptyDatabaseThenInit(t *testing.T) {
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
	schema := "pqcota_invcmd_" + strconv.FormatInt(time.Now().UnixNano(), 36)
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

	code, _, errOut := runInventory(t, scoped)
	if code != 1 || !strings.Contains(errOut, "-init-schema") || !strings.Contains(errOut, "inventory schema is missing") {
		t.Fatalf("query on an empty schema: exit %d, stderr %q", code, errOut)
	}
	if n := tables(); n != 0 {
		t.Fatalf("the query created %d tables", n)
	}

	code, out, errOut := runInventory(t, scoped, "-init-schema")
	if code != 0 {
		t.Fatalf("-init-schema: exit %d, stderr %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if last := lines[len(lines)-1]; last != "schema ready: 11 created, 0 already present" {
		t.Fatalf("success line: %q", out)
	}
	if n := tables(); n != 11 {
		t.Fatalf("tables after init: %d", n)
	}

	code, out, errOut = runInventory(t, scoped, "-init-schema")
	if code != 0 || !strings.HasSuffix(strings.TrimSpace(out), "schema ready: 0 created, 11 already present") {
		t.Fatalf("second -init-schema: exit %d, %q %q", code, out, errOut)
	}

	code, out, errOut = runInventory(t, scoped)
	if code != 0 || !strings.Contains(out, "0 nodes") {
		t.Fatalf("query after init: exit %d, %q %q", code, out, errOut)
	}
}
