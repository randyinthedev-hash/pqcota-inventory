// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
)

// 이 명령은 PQCOTA_ORG를 읽는다. 읽지 않던 때(v0.10.0 이전)는 조직을 정해 둬도 기본 조직에 써서
// 조회 쪽이 그 데이터를 못 봤고, PQCOTA_REQUIRE_ORG=1이면 조직을 줘도 열리지 않았다.

// 조직 규칙을 어기면 DB에 닿기 전에 막힌다 — Postgres 없이 도는 시험.
func TestMetaStoreHonoursTheOrganizationRules(t *testing.T) {
	const noDB = "postgres://nobody@127.0.0.1:1/none" // 규칙 검사가 먼저라 연결하지 않는다

	t.Run("required but not named", func(t *testing.T) {
		t.Setenv(org.RequireEnv, "1")
		t.Setenv(org.Env, "")
		if _, err := openMetaStore(context.Background(), noDB); !errors.Is(err, org.ErrDefaultNotAllowed) {
			t.Fatalf("PQCOTA_REQUIRE_ORG=1 without PQCOTA_ORG must refuse to open, got %v", err)
		}
	})
	t.Run("required and default named explicitly", func(t *testing.T) {
		t.Setenv(org.RequireEnv, "1")
		t.Setenv(org.Env, string(org.Default))
		if _, err := openMetaStore(context.Background(), noDB); !errors.Is(err, org.ErrReserved) {
			t.Fatalf("naming the default organization is refused when an organization is required, got %v", err)
		}
	})
	t.Run("badly shaped name is never replaced by the default", func(t *testing.T) {
		t.Setenv(org.RequireEnv, "")
		t.Setenv(org.Env, "Acme")
		if _, err := openMetaStore(context.Background(), noDB); !errors.Is(err, org.ErrShape) {
			t.Fatalf("a badly shaped PQCOTA_ORG is always an error, got %v", err)
		}
	})
}

// 기본 조직·명시한 조직·필수 모드에서 실제로 어느 조직에 쓰는지 — Postgres에서만 잴 수 있다.
// PQCOTA_TEST_DSN이 있을 때만 돈다. 스킵은 통과가 아니다.
func TestMetaStoreWritesToTheNamedOrganization(t *testing.T) {
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	ctx := context.Background()
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)

	t.Run("no organization named: the default", func(t *testing.T) {
		t.Setenv(org.RequireEnv, "")
		t.Setenv(org.Env, "")
		m, err := openMetaStore(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		if m.Org() != org.Default {
			t.Fatalf("Org() = %q, want the default organization", m.Org())
		}
	})

	t.Run("named organization, also when one is required", func(t *testing.T) {
		name := "meta-" + stamp
		t.Setenv(org.RequireEnv, "1")
		t.Setenv(org.Env, name)
		m, err := openMetaStore(ctx, dsn)
		if err != nil {
			t.Fatalf("a named organization must open even with PQCOTA_REQUIRE_ORG=1: %v", err)
		}
		defer m.Close()
		if string(m.Org()) != name {
			t.Fatalf("Org() = %q, want %q", m.Org(), name)
		}

		// 쓴 것이 그 조직에서 보이고 기본 조직에서는 보이지 않는다.
		node := "node-" + stamp
		if err := write(m, node); err != nil {
			t.Fatal(err)
		}
		if got := read(t, m, node); !got {
			t.Fatal("what was written is not visible in the organization it was written to")
		}
		t.Setenv(org.RequireEnv, "") // 필수 모드에서는 기본 조직을 열 수 없으니 비교용으로만 푼다
		def, err := inventory.NewPgMetaStoreIn(ctx, dsn, "")
		if err != nil {
			t.Fatal(err)
		}
		defer def.Close()
		if read(t, def, node) {
			t.Fatal("it was written to the default organization instead of the named one")
		}
	})
}

func write(m *inventory.PgMetaStore, node string) error {
	return m.UpsertProfile(&inventoryv1.MachineProfile{NodeId: node, DisplayName: node})
}

func read(t *testing.T, m *inventory.PgMetaStore, node string) bool {
	t.Helper()
	p, err := m.Profile(node)
	if err != nil {
		t.Fatal(err)
	}
	return p != nil
}
