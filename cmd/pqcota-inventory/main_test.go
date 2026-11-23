// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/pgschema/pgschematest"
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

// 커밋 결과를 받지 못하면 성공 줄 없이 종료 1이고, 연결을 복구해 다시 돌리라고 안내한다.
func TestInitCommitUnknownPrintsNoSuccess(t *testing.T) {
	c := &pgschematest.Conn{CommitErr: fmt.Errorf("conn closed: %w", io.ErrUnexpectedEOF)}
	var o, e strings.Builder
	code := runInit(context.Background(), c, &o, &e)
	if code != 1 || o.Len() != 0 {
		t.Fatalf("exit %d, stdout %q", code, o.String())
	}
	if !strings.Contains(e.String(), "restore the connection and run -init-schema again") || strings.Contains(e.String(), "nothing was changed") {
		t.Fatalf("stderr: %q", e.String())
	}
}

// T10: -topology는 다른 조회 옵션·인자와 함께 오면 접속하기 전에 종료 2.
func TestTopologyRefusesOtherArguments(t *testing.T) {
	unreachable := "postgres://nobody@127.0.0.1:1/none?connect_timeout=1"
	for name, args := range map[string][]string{
		"-history":     {"-topology", "-", "-history", "web-01"},
		"-snapshot":    {"-topology", "-", "-snapshot", "s1"},
		"-diff":        {"-topology", "-", "-diff", "a,b"},
		"an argument":  {"-topology", "-", "extra"},
		"-init-schema": {"-init-schema", "-topology", "-"},
	} {
		code, out, errOut := runInventory(t, unreachable, args...)
		if code != 2 || strings.Contains(out, "digraph") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, out, errOut)
		}
	}
}

// T10: 출력 자리. "-"면 DOT는 표준 출력, 요약은 표준 오류. 경로면 파일에 쓰고 요약은 표준 출력.
func TestTopologyOutputs(t *testing.T) {
	store := history.NewMemStore()
	if err := store.Append(&history.Snapshot{ID: "s1", NodeID: "web-01", RulesetVersion: "r", Edges: []*discoveryv1.ObservedEdge{
		{SrcNodeId: "web-01", DstAddr: "10.0.1.20:443", Port: 443, Role: discoveryv1.EdgeRole_EDGE_ROLE_CLIENT, ObservedCount: 2},
	}}); err != nil {
		t.Fatal(err)
	}
	var o, e strings.Builder
	if code := topologyTo(store, nil, "-", &o, &e); code != 0 || !strings.HasPrefix(o.String(), "digraph pqcota_topology {") ||
		e.String() != "topology: 1 nodes · 1 lines (one per stored record) · 1 address boxes\n" {
		t.Fatalf("stdout mode: exit %d, stdout %q, stderr %q", code, o.String(), e.String())
	}
	path := filepath.Join(t.TempDir(), "topo.dot")
	o.Reset()
	e.Reset()
	if code := topologyTo(store, nil, path, &o, &e); code != 0 || e.Len() != 0 || !strings.Contains(o.String(), "→ "+path) {
		t.Fatalf("file mode: exit %d, stdout %q, stderr %q", code, o.String(), e.String())
	}
	if b, err := os.ReadFile(path); err != nil || !strings.HasPrefix(string(b), "digraph") {
		t.Fatalf("file: %v %q", err, b)
	}
}

// T10·T2(PostgreSQL): 빈 스키마에서는 표를 만들지 않고 종료 1. 초기화하고 양쪽 기록을 적재하면 선이 둘이고 횟수는
// 기록마다 ×3이다(합치지 않음). 등록 IP로 상대가 이어진다(Pg의 Endpoints).
func TestTopologyPostgres(t *testing.T) {
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
	schema := "pqcota_topo_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	scoped := dsn + sep + "search_path=" + schema

	code, out, errOut := runInventory(t, scoped, "-topology", "-")
	if code != 1 || strings.Contains(out, "digraph") || !strings.Contains(errOut, "inventory schema is missing") {
		t.Fatalf("empty schema: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	var n int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname=$1`, schema).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tables after -topology on an empty schema: %d (%v)", n, err)
	}
	if code, _, errOut := runInventory(t, scoped, "-init-schema"); code != 0 {
		t.Fatalf("-init-schema: %d %q", code, errOut)
	}

	hist, err := history.OpenPgStoreIn(ctx, scoped, "acme")
	if err != nil {
		t.Fatal(err)
	}
	defer hist.Close()
	meta, err := inventory.OpenPgMetaStoreIn(ctx, scoped, "acme")
	if err != nil {
		t.Fatal(err)
	}
	defer meta.Close()
	tls := discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS
	for _, s := range []*history.Snapshot{
		{ID: "s-web-01", NodeID: "web-01", RulesetVersion: "r", Edges: []*discoveryv1.ObservedEdge{{SrcNodeId: "web-01", DstAddr: "10.0.1.20:443",
			Port: 443, Role: discoveryv1.EdgeRole_EDGE_ROLE_CLIENT, Protocol: tls, NegotiatedGroup: "X25519MLKEM768", AppKey: "/usr/bin/openssl", ObservedCount: 3}}},
		{ID: "s-web-02", NodeID: "web-02", RulesetVersion: "r", Edges: []*discoveryv1.ObservedEdge{{SrcNodeId: "web-02", DstAddr: "10.0.1.10",
			Port: 443, Role: discoveryv1.EdgeRole_EDGE_ROLE_SERVER, Protocol: tls, NegotiatedGroup: "X25519MLKEM768", AppKey: "/usr/sbin/nginx", ObservedCount: 3}}},
	} {
		if err := hist.Append(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []*inventoryv1.MachineEndpoint{{NodeId: "web-02", Ip: "10.0.1.20"}, {NodeId: "web-01", Ip: "10.0.1.10"}} {
		if err := meta.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if eps, err := meta.Endpoints(); err != nil || len(eps) != 2 || eps[0].GetNodeId() != "web-01" {
		t.Fatalf("Pg Endpoints: %v %v", eps, err)
	}

	code, out, errOut = runInventory(t, scoped, "-topology", "-")
	if code != 0 || errOut != "topology: 2 nodes · 2 lines (one per stored record) · 0 address boxes\n" {
		t.Fatalf("-topology: exit %d, stderr %q\n%s", code, errOut, out)
	}
	for _, want := range []string{
		`"app|6:web-01|/usr/bin/openssl" -> "node|web-02" [label="tls :443 · X25519MLKEM768 · ×3\nseen by web-01 as client"`,
		`"node|web-01" -> "app|6:web-02|/usr/sbin/nginx" [label="tls :443 · X25519MLKEM768 · ×3\nseen by web-02 as server"`,
		`\nlast loaded 20`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "×6") {
		t.Error("the two records' counts were added up")
	}
}
