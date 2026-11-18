// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package pgschematest — pgschema.Init을 데이터베이스 없이 시험하는 연결. 실행·커밋 오류를 마음대로 낸다.
// 실제 Postgres로는 「서버가 커밋한 뒤 연결이 끊겼다」를 안정적으로 만들 수 없어서 둔다. 시험에서만 쓴다.
package pgschematest

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Conn — pgschema.Conn. 표는 하나도 없는 것으로 답한다.
type Conn struct {
	ExecErr   error // 첫 Exec가 돌려줄 오류
	CommitErr error // Commit이 돌려줄 오류
	Execs     int
	Committed bool // Commit이 불렸는가(오류를 돌려줬어도)
}

func (c *Conn) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row { return zeroRow{} }

func (c *Conn) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, errors.New("pgschematest: Query is not supported")
}

func (c *Conn) Begin(ctx context.Context) (pgx.Tx, error) { return &tx{c: c}, nil }

// zeroRow — 정수는 0으로 채운다(「그런 표 없음」).
type zeroRow struct{}

func (zeroRow) Scan(dest ...any) error {
	for _, d := range dest {
		if p, ok := d.(*int); ok {
			*p = 0
		}
	}
	return nil
}

type tx struct {
	pgx.Tx // 쓰지 않는 메서드. 부르면 nil 역참조로 시험이 깨진다
	c      *Conn
}

func (t *tx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	t.c.Execs++
	if t.c.ExecErr != nil {
		return pgconn.CommandTag{}, t.c.ExecErr
	}
	return pgconn.CommandTag{}, nil
}

func (t *tx) Commit(ctx context.Context) error {
	t.c.Committed = true
	return t.c.CommitErr
}

func (t *tx) Rollback(ctx context.Context) error { return nil }
