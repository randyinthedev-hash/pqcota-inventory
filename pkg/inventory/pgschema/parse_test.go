// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package pgschema

import (
	"reflect"
	"testing"
)

// 스키마 SQL에서 표·열을 뽑는다. 제약 줄·주석·인덱스는 열이 아니다.
func TestParse(t *testing.T) {
	sql := `
CREATE TABLE IF NOT EXISTS t_one (
    seq   BIGSERIAL PRIMARY KEY,
    id    TEXT NOT NULL,  -- 꼬리 주석
    -- 주석 줄
    body  JSONB,
    PRIMARY KEY (a, b),
    UNIQUE (org, id),
    FOREIGN KEY (org, x) REFERENCES other(org, y)
);
CREATE INDEX IF NOT EXISTS idx_one ON t_one(id);
-- ALTER TABLE t_one ADD COLUMN IF NOT EXISTS commented TEXT;
ALTER TABLE t_one        ADD COLUMN IF NOT EXISTS org TEXT NOT NULL DEFAULT 'default';
ALTER TABLE t_one ADD COLUMN IF NOT EXISTS id TEXT;
ALTER TABLE t_two ADD COLUMN IF NOT EXISTS late TEXT;
`
	got := Parse(sql)
	want := []Table{
		{Name: "t_one", Columns: []string{"seq", "id", "body", "org"}},
		{Name: "t_two", Columns: []string{"late"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// 권한 문제가 하나라도 있으면 초기화를 권하지 않는다 — 없는 표가 함께 있어도 그렇다.
func TestProblemClassification(t *testing.T) {
	m := &Problem{Missing: []string{"pqcota_x"}, Hint: "run init"}
	if !isErr(m, ErrMissing) || isErr(m, ErrPermission) {
		t.Fatal("missing only must be ErrMissing")
	}
	if got := m.Error(); got != "inventory schema is missing: pqcota_x not found — run init" {
		t.Fatalf("message: %s", got)
	}
	d := &Problem{Missing: []string{"pqcota_x"}, Denied: []string{"SELECT on pqcota_y"}, Hint: "run init"}
	if !isErr(d, ErrPermission) || isErr(d, ErrMissing) {
		t.Fatal("any denial must be ErrPermission")
	}
	if msg := d.Error(); contains(msg, "run init") {
		t.Fatalf("a permission problem must not suggest initializing: %s", msg)
	}
}

func isErr(p *Problem, target error) bool { return p.Is(target) }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
