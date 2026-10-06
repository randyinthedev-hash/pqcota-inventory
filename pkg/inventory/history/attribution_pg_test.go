// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package history_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// TestPgAttributionsShareATableAndStillDoNotSeeEachOther — **격리의 진짜 시험은 여기다.**
//
// 인메모리 쪽 테스트는 저장소 객체가 달라서 통과한다 — 모양은 확인해도 격리를 증명하지 못한다.
// 두 조직이 **한 테이블**을 공유하면서도 서로를 못 보는지는 Postgres에서만 잴 수 있다.
// 히스토리에는 이 짝이 있었는데(TV-ORG-4) 선언 저장소에는 없었다.
//
// PQCOTA_TEST_DSN이 있을 때만 돈다. 스킵은 통과가 아니다.
func TestPgAttributionsShareATableAndStillDoNotSeeEachOther(t *testing.T) {
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	ctx := context.Background()
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	a, err := history.NewPgStoreIn(ctx, dsn, "attr-a-"+stamp)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := history.NewPgStoreIn(ctx, dsn, "attr-b-"+stamp)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// 두 조직이 **같은 (node, dst)**를 선언한다 — 키가 겹치는 최악의 경우다.
	const node, dst = "web-01", "10.0.0.7:22"
	if err := a.PutAttribution(history.EdgeAttribution{NodeID: node, Dst: dst, AppKey: "a-owns.service"}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutAttribution(history.EdgeAttribution{NodeID: node, Dst: dst, AppKey: "b-owns.service"}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ store, want string }{
		{"a", "a-owns.service"},
		{"b", "b-owns.service"},
	} {
		st := a
		if tc.store == "b" {
			st = b
		}
		got, err := st.Attributions()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("organization %s sees %d — someone else's declarations got mixed in: %+v", tc.store, len(got), got)
		}
		if got[0].AppKey != tc.want {
			t.Fatalf("organization %s sees %q — it must be %q", tc.store, got[0].AppKey, tc.want)
		}
	}
}

// TestPgRedeclaringOverwrites — Pg의 ON CONFLICT 경로는 인메모리와 구현이 다르다.
//
// 선언은 사람이 고치는 것이라 덮어쓴다 — 관측(append-only)과 규칙이 다르므로, 그 차이가
// 저장소를 바꿔도 유지되는지 따로 확인한다.
func TestPgRedeclaringOverwrites(t *testing.T) {
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	ctx := context.Background()
	st, err := history.NewPgStoreIn(ctx, dsn, "attr-ovw-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const node, dst = "web-01", "10.0.0.9:443"
	for _, key := range []string{"first.service", "second.service"} {
		if err := st.PutAttribution(history.EdgeAttribution{NodeID: node, Dst: dst, AppKey: key}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.Attributions()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("the same edge was declared twice and %d rows piled up — it must overwrite", len(got))
	}
	if got[0].AppKey != "second.service" {
		t.Fatalf("the later declaration did not win: %q", got[0].AppKey)
	}
	if got[0].DeclaredAt.IsZero() {
		t.Error("the declaration timestamp is empty — when it was corrected must be recorded")
	}
}
