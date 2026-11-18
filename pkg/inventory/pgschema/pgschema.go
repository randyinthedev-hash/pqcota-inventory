// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package pgschema — 저장소 스키마를 DDL 없이 확인하고, 초기화(-init-schema)를 한 트랜잭션으로 돌린다.
//
// 확인은 세 가지를 가른다. 표·열이 없으면 [ErrMissing](초기화로 고친다). 표는 있는데 권한이 없으면
// [ErrPermission](초기화와 무관하다 — 초기화를 권하면 안 된다). 접속·인증·그 밖의 SQL 오류는 그대로 돌려준다.
//
// 확인할 표·열은 각 저장소의 스키마 SQL에서 뽑는다([Parse]). 목록을 손으로 따로 두면 열을 더하는 날 어긋난다.
package pgschema

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrMissing — 필요한 표나 열이 없다. 초기화(또는 판을 올린 뒤의 재초기화)가 필요하다.
var ErrMissing = errors.New("inventory schema is missing")

// ErrPermission — 표·스키마는 있는데 이 계정에 권한이 없다. 초기화로 고쳐지지 않는다.
var ErrPermission = errors.New("no privilege on the inventory schema")

// Table — 표 이름과 그 표에 있어야 하는 열.
type Table struct {
	Name    string
	Columns []string
}

// Part — 한 저장소가 맡은 스키마. SQL은 멱등 DDL이고, Tables는 그 SQL에서 뽑은 것이다.
type Part struct {
	Name   string
	SQL    string
	Tables []Table
}

// NewPart — SQL에서 표·열을 뽑아 Part를 만든다.
func NewPart(name, sql string) Part { return Part{Name: name, SQL: sql, Tables: Parse(sql)} }

var (
	reCreate = regexp.MustCompile(`(?i)^CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\(`)
	reAdd    = regexp.MustCompile(`(?i)ALTER TABLE\s+(\w+)\s+ADD COLUMN IF NOT EXISTS\s+(\w+)`)
	reNotCol = regexp.MustCompile(`(?i)^(PRIMARY|UNIQUE|FOREIGN|CONSTRAINT|CHECK|EXCLUDE)\b`)
)

// Parse — 멱등 DDL에서 표와 열을 뽑는다. `CREATE TABLE IF NOT EXISTS t (…);`의 열 정의와
// `ALTER TABLE t ADD COLUMN IF NOT EXISTS c`를 읽는다. 주석 줄은 건너뛴다.
func Parse(sql string) []Table {
	cols := map[string][]string{}
	var order []string
	add := func(t, c string) {
		if _, ok := cols[t]; !ok {
			order = append(order, t)
			cols[t] = nil
		}
		if c == "" {
			return
		}
		for _, x := range cols[t] {
			if x == c {
				return
			}
		}
		cols[t] = append(cols[t], c)
	}
	in := ""
	for _, raw := range strings.Split(sql, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		if in != "" {
			if strings.HasPrefix(line, ")") {
				in = ""
				continue
			}
			if reNotCol.MatchString(line) {
				continue
			}
			add(in, strings.Fields(line)[0])
			continue
		}
		if m := reCreate.FindStringSubmatch(line); m != nil {
			in = m[1]
			add(in, "")
			continue
		}
		for _, m := range reAdd.FindAllStringSubmatch(line, -1) {
			add(m[1], m[2])
		}
	}
	out := make([]Table, 0, len(order))
	for _, t := range order {
		out = append(out, Table{Name: t, Columns: cols[t]})
	}
	return out
}

// ErrRolledBack — 초기화가 커밋 전에 실패해 되돌려졌다. 데이터베이스는 실행 전과 같다.
var ErrRolledBack = errors.New("rolled back, nothing was changed")

// Querier — *pgxpool.Pool, *pgx.Conn, pgx.Tx 모두 된다.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Problem — 확인에서 나온 것. errors.Is(err, ErrMissing) / errors.Is(err, ErrPermission)로 가른다.
type Problem struct {
	Missing []string // "pqcota_x" 또는 "pqcota_x.col"
	Denied  []string // "SELECT on pqcota_x", "USAGE on schema s"
	Hint    string   // ErrMissing일 때만 붙인다
}

func (p *Problem) Error() string {
	if len(p.Denied) > 0 {
		// 권한 문제가 하나라도 있으면 초기화를 권하지 않는다. 없는 표가 함께 있어도 권한이 먼저다 —
		// 그 계정으로는 초기화도 못 하거나, 해도 여전히 읽지 못한다.
		msg := fmt.Sprintf("%s: this account lacks %s", ErrPermission, strings.Join(p.Denied, ", "))
		if len(p.Missing) > 0 {
			msg += fmt.Sprintf(" (also not found: %s)", strings.Join(p.Missing, ", "))
		}
		return msg + " — grant the privileges to this account; initializing the schema does not change them"
	}
	msg := fmt.Sprintf("%s: %s not found", ErrMissing, strings.Join(p.Missing, ", "))
	if p.Hint != "" {
		msg += " — " + p.Hint
	}
	return msg
}

func (p *Problem) Is(target error) bool {
	if len(p.Denied) > 0 {
		return target == ErrPermission
	}
	return target == ErrMissing
}

// Check — DDL 없이 표·열·SELECT 권한을 본다. 문제가 없으면 nil.
//
// 표는 search_path(current_schemas)에서 찾는다. USAGE가 없는 스키마는 current_schemas에서 빠지므로,
// 찾지 못한 표는 search_path의 USAGE 없는 스키마에 같은 이름이 있는지 따로 보아 권한 문제로 가른다.
// 열은 pg_attribute로 본다 — information_schema는 권한 있는 열만 보여 준다.
func Check(ctx context.Context, q Querier, tables []Table, hint string) error {
	path, err := rawSearchPath(ctx, q)
	if err != nil {
		return err
	}
	p := &Problem{Hint: hint}
	for _, t := range tables {
		var oid uint32
		var ok bool
		err := q.QueryRow(ctx, `
SELECT c.oid, has_table_privilege(c.oid, 'SELECT')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relname = $1 AND c.relkind IN ('r','p') AND n.nspname = ANY(current_schemas(false))
 ORDER BY array_position(current_schemas(false), n.nspname::text) LIMIT 1`, t.Name).Scan(&oid, &ok)
		if errors.Is(err, pgx.ErrNoRows) {
			var hidden string
			herr := q.QueryRow(ctx, `
SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relname = $1 AND c.relkind IN ('r','p') AND n.nspname = ANY($2::text[])
   AND NOT has_schema_privilege(n.oid, 'USAGE') LIMIT 1`, t.Name, path).Scan(&hidden)
			switch {
			case herr == nil:
				p.Denied = appendOnce(p.Denied, "USAGE on schema "+hidden)
			case errors.Is(herr, pgx.ErrNoRows):
				p.Missing = append(p.Missing, t.Name)
			default:
				return herr
			}
			continue
		}
		if err != nil {
			return err
		}
		if !ok {
			p.Denied = append(p.Denied, "SELECT on "+t.Name)
		}
		have, err := columns(ctx, q, oid)
		if err != nil {
			return err
		}
		for _, c := range t.Columns {
			if !have[c] {
				p.Missing = append(p.Missing, t.Name+"."+c)
			}
		}
	}
	if len(p.Missing) == 0 && len(p.Denied) == 0 {
		return nil
	}
	return p
}

func columns(ctx context.Context, q Querier, oid uint32) (map[string]bool, error) {
	rows, err := q.Query(ctx, `SELECT attname FROM pg_attribute WHERE attrelid = $1 AND attnum > 0 AND NOT attisdropped`, oid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		have[c] = true
	}
	return have, rows.Err()
}

// rawSearchPath — USAGE와 상관없이 search_path에 적힌 스키마 이름. "$user"는 지금 사용자로 편다.
func rawSearchPath(ctx context.Context, q Querier) ([]string, error) {
	var sp, user string
	if err := q.QueryRow(ctx, `SELECT current_setting('search_path'), current_user`).Scan(&sp, &user); err != nil {
		return nil, err
	}
	var out []string
	for _, s := range strings.Split(sp, ",") {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) && len(s) >= 2 {
			s = strings.ReplaceAll(s[1:len(s)-1], `""`, `"`)
		}
		if s == "$user" {
			s = user
		}
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

func appendOnce(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// Conn — 초기화에 필요한 것: 트랜잭션을 열 수 있고 조회할 수 있다(*pgxpool.Pool).
type Conn interface {
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Report — 초기화 결과. 커밋하고 다시 확인한 뒤에만 채워진다.
type Report struct {
	Created  []string
	Existing []string
}

// Init — 여러 Part의 DDL을 **한 트랜잭션으로** 돌리고, 커밋한 뒤 모든 표·열을 다시 확인한다.
// 중간에 실패하면 되돌려지고(PostgreSQL의 DDL은 트랜잭션 안에 든다) 아무것도 남지 않는다.
// 돌려준 Report는 커밋과 재확인이 모두 성공했을 때만 의미가 있다.
//
// GATE: 배선 필수 — pqcota-inventory -init-schema, pqcota-records -init-schema.
func Init(ctx context.Context, c Conn, parts ...Part) (Report, error) {
	var all []Table
	for _, p := range parts {
		all = append(all, p.Tables...)
	}
	before := map[string]bool{}
	for _, t := range all {
		var n int
		if err := c.QueryRow(ctx, `
SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relname = $1 AND c.relkind IN ('r','p') AND n.nspname = ANY(current_schemas(false))`, t.Name).Scan(&n); err != nil {
			return Report{}, err
		}
		before[t.Name] = n > 0
	}
	tx, err := c.Begin(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("%w (%w)", err, ErrRolledBack)
	}
	defer tx.Rollback(ctx) // 커밋한 뒤에는 아무것도 하지 않는다
	for _, p := range parts {
		if _, err := tx.Exec(ctx, p.SQL); err != nil {
			return Report{}, fmt.Errorf("%s schema: %w (%w)", p.Name, err, ErrRolledBack)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Report{}, fmt.Errorf("commit: %w (%w)", err, ErrRolledBack)
	}
	if err := Check(ctx, c, all, ""); err != nil {
		return Report{}, fmt.Errorf("after initializing: %w", err)
	}
	var r Report
	for _, t := range all {
		if before[t.Name] {
			r.Existing = append(r.Existing, t.Name)
		} else {
			r.Created = append(r.Created, t.Name)
		}
	}
	sort.Strings(r.Created)
	sort.Strings(r.Existing)
	return r, nil
}

// IsPrivilegeError — PostgreSQL이 권한 부족(42501)으로 거절했는가. 초기화가 「소유자가 아니다」로 실패한 것을 가린다.
func IsPrivilegeError(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "42501"
}

// FormatReport — -init-schema의 출력. 마지막 줄이 성공 줄이다.
func FormatReport(r Report) string {
	var b strings.Builder
	if len(r.Created) > 0 {
		fmt.Fprintf(&b, "created: %s\n", strings.Join(r.Created, ", "))
	}
	if len(r.Existing) > 0 {
		fmt.Fprintf(&b, "already present (brought up to date): %s\n", strings.Join(r.Existing, ", "))
	}
	fmt.Fprintf(&b, "schema ready: %d created, %d already present\n", len(r.Created), len(r.Existing))
	return b.String()
}
