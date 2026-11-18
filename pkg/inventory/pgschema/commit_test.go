// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package pgschema_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/pgschema"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/pgschema/pgschematest"
)

var part = pgschema.NewPart("t", "CREATE TABLE IF NOT EXISTS pqcota_t (\n    id TEXT\n);\n")

// 커밋을 보냈는데 결과를 받지 못하면(연결이 끊김) 서버가 커밋했을 수도 있다. 「아무것도 바뀌지 않았다」고 하지 않고,
// 연결을 복구해 다시 돌리라고 한다. 보고서는 비어 있다(성공 줄을 낼 근거가 없다).
func TestInitCommitResultUnknown(t *testing.T) {
	c := &pgschematest.Conn{CommitErr: fmt.Errorf("conn closed: %w", io.ErrUnexpectedEOF)}
	rep, err := pgschema.Init(context.Background(), c, part)
	if !c.Committed {
		t.Fatal("commit was not attempted")
	}
	if !errors.Is(err, pgschema.ErrCommitUnknown) || errors.Is(err, pgschema.ErrRolledBack) {
		t.Fatalf("want ErrCommitUnknown only, got %v", err)
	}
	for _, w := range []string{"could not confirm", "restore the connection and run -init-schema again"} {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("message lacks %q: %v", w, err)
		}
	}
	if strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("an unknown commit must not claim nothing changed: %v", err)
	}
	if len(rep.Created)+len(rep.Existing) != 0 {
		t.Fatalf("report: %+v", rep)
	}
}

// 서버가 COMMIT에 오류로 답했으면 되돌려진 것이다.
func TestInitCommitRefusedByServer(t *testing.T) {
	c := &pgschematest.Conn{CommitErr: &pgconn.PgError{Code: "40001", Message: "could not serialize"}}
	_, err := pgschema.Init(context.Background(), c, part)
	if !errors.Is(err, pgschema.ErrRolledBack) || errors.Is(err, pgschema.ErrCommitUnknown) {
		t.Fatalf("want ErrRolledBack, got %v", err)
	}
}

// DDL 실행 중 실패하면 커밋하지 않고 되돌린다.
func TestInitExecFailureRollsBack(t *testing.T) {
	c := &pgschematest.Conn{ExecErr: &pgconn.PgError{Code: "42501", Message: "must be owner of table pqcota_t"}}
	_, err := pgschema.Init(context.Background(), c, part)
	if c.Committed {
		t.Fatal("committed after a failed statement")
	}
	if !errors.Is(err, pgschema.ErrRolledBack) || !pgschema.IsPrivilegeError(err) {
		t.Fatalf("want ErrRolledBack and a privilege error, got %v", err)
	}
}
