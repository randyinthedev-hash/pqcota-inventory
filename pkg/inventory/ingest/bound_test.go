// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/declaration"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/ingest"
)

// boundOpts — ID 결합 모드. PQCOTA_REQUIRE_SIGNATURE는 켜지 않는다(결합 모드에서는 서명이 그와 무관하게 필수다).
func boundOpts(store *history.MemStore, keys map[string][]string) ingest.IngestOptions {
	o := opts(store)
	o.VerifyCollector = func(r *discoveryv1.CollectionResult) error { return sign.VerifyBound(keys, r) }
	o.Rejections = store
	return o
}

func legacyOpts(store *history.MemStore, keys []string) ingest.IngestOptions {
	o := opts(store)
	o.VerifySig = func(r *discoveryv1.CollectionResult) bool { return sign.Verify(keys, r) }
	o.Rejections = store
	return o
}

func signAs(t *testing.T, r *discoveryv1.CollectionResult, id, priv string) *discoveryv1.CollectionResult {
	t.Helper()
	r.Envelope.CollectorId = id
	if err := sign.SignAll(priv, []*discoveryv1.CollectionResult{r}); err != nil {
		t.Fatal(err)
	}
	return r
}

func snapshots(t *testing.T, s *history.MemStore, node string) int {
	t.Helper()
	ss, err := s.Snapshots(node)
	if err != nil {
		t.Fatal(err)
	}
	return len(ss)
}

func lastRejection(t *testing.T, s *history.MemStore) history.Rejection {
	t.Helper()
	rs, err := s.Rejections(0)
	if err != nil || len(rs) == 0 {
		t.Fatalf("no rejection recorded: %v", err)
	}
	return rs[0]
}

// 핵심: 키 K를 openssl-collector에만 등록했다. K로 서명한 자기 ID의 결과는 적재되고, 같은 K로 network-collector를
// 단 결과는 정규화·스냅샷 전에 거부된다. 거절 기록의 사유가 두 ID를 말한다.
func TestBoundSameKeyOwnIDAcceptedOtherIDRejected(t *testing.T) {
	k, kPriv, _ := sign.Generate()
	keys := map[string][]string{"openssl-collector": {k}}

	store := history.NewMemStore()
	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{signAs(t, opensslResult("web-01", "libssl.so.3"), "openssl-collector", kPriv)}, boundOpts(store, keys))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accepted != 1 || rep.Rejected != 0 || snapshots(t, store, "web-01") != 1 {
		t.Fatalf("its own ID with its own key was not ingested: %+v", rep)
	}

	store = history.NewMemStore()
	rep, err = ingest.IngestWith([]*discoveryv1.CollectionResult{signAs(t, opensslResult("web-01", "libssl.so.3"), "network-collector", kPriv)}, boundOpts(store, keys))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accepted != 0 || rep.Rejected != 1 || snapshots(t, store, "web-01") != 0 {
		t.Fatalf("a result with another collector ID was stored: %+v", rep)
	}
	r := lastRejection(t, store)
	if r.Kind != history.RejectSignature || r.CollectorID != "network-collector" || !strings.Contains(r.Reason, "collector \"network-collector\" has no registered key") {
		t.Errorf("rejection: %+v", r)
	}

	// network-collector에도 다른 키가 등록돼 있으면 사유가 「다른 ID의 키로는 맞는다」를 덧붙인다.
	k2, _, _ := sign.Generate()
	keys["network-collector"] = []string{k2}
	store = history.NewMemStore()
	if _, err := ingest.IngestWith([]*discoveryv1.CollectionResult{signAs(t, opensslResult("web-01", "libssl.so.3"), "network-collector", kPriv)}, boundOpts(store, keys)); err != nil {
		t.Fatal(err)
	}
	r = lastRejection(t, store)
	if snapshots(t, store, "web-01") != 0 ||
		!strings.Contains(r.Reason, "does not match the keys registered for network-collector") ||
		!strings.Contains(r.Reason, "matches a key registered for openssl-collector") {
		t.Errorf("rejection: %+v", r)
	}
}

// 결합 모드에서는 PQCOTA_REQUIRE_SIGNATURE가 꺼져 있어도 서명 없는 결과를 받지 않는다. 「검증하지 않고 받음」이 없다.
func TestBoundUnsignedRejectedWithoutRequireSignature(t *testing.T) {
	k, _, _ := sign.Generate()
	store := history.NewMemStore()
	o := boundOpts(store, map[string][]string{"openssl-collector": {k}})
	if o.RequireSignature {
		t.Fatal("premise: RequireSignature is off")
	}
	unsigned := opensslResult("web-01", "libssl.so.3")
	unsigned.Envelope.CollectorId = "openssl-collector"
	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{unsigned}, o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Rejected != 1 || rep.Unverified != 0 || rep.Accepted != 0 || snapshots(t, store, "web-01") != 0 {
		t.Fatalf("an unsigned result was taken in bound mode: %+v", rep)
	}
	if r := lastRejection(t, store); r.Kind != history.RejectSignature || r.Reason != "no signature" {
		t.Errorf("rejection: %+v", r)
	}
}

// 앱 선언·자산 선언도 결합 모드에서는 서명을 지난다. 서명이 없거나 다른 ID의 키로 서명했으면 저장된 것이 0건이다.
func TestBoundDeclarationsRejectedStoreNothing(t *testing.T) {
	attrKey, attrPriv, _ := sign.Generate()
	declKey, declPriv, _ := sign.Generate()
	keys := map[string][]string{"attribution-importer": {attrKey}, "declaration-importer": {declKey}}

	attr := func() *discoveryv1.CollectionResult {
		rs, err := declaration.ImportAttributionCSV(strings.NewReader("web-01,10.0.0.9:443,billing\n"))
		if err != nil || len(rs) != 1 {
			t.Fatalf("attribution: %v %d", err, len(rs))
		}
		return rs[0]
	}
	decl := func() *discoveryv1.CollectionResult {
		rs, err := declaration.ImportCSV(strings.NewReader("web-01,openssl,libssl.so.3\n"))
		if err != nil || len(rs) != 1 {
			t.Fatalf("declaration: %v %d", err, len(rs))
		}
		return rs[0]
	}
	signed := func(r *discoveryv1.CollectionResult, priv string) *discoveryv1.CollectionResult {
		if err := sign.SignAll(priv, []*discoveryv1.CollectionResult{r}); err != nil {
			t.Fatal(err)
		}
		return r
	}

	for name, in := range map[string][]*discoveryv1.CollectionResult{
		"unsigned":                 {attr(), decl()},
		"signed with the other ID": {signed(attr(), declPriv), signed(decl(), attrPriv)},
	} {
		store := history.NewMemStore()
		rep, err := ingest.IngestWith(in, boundOpts(store, keys))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		as, _ := store.Attributions()
		if len(as) != 0 || rep.DeclaredAttributions != 0 || snapshots(t, store, "web-01") != 0 || rep.Rejected != 2 {
			t.Errorf("%s: something was stored — attributions %d, snapshots %d, report %+v", name, len(as), snapshots(t, store, "web-01"), rep)
		}
	}

	// 자기 키로 서명하면 둘 다 들어간다.
	store := history.NewMemStore()
	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{signed(attr(), attrPriv), signed(decl(), declPriv)}, boundOpts(store, keys))
	if err != nil {
		t.Fatal(err)
	}
	as, _ := store.Attributions()
	if len(as) != 1 || rep.DeclaredAttributions != 1 || snapshots(t, store, "web-01") != 1 || rep.Rejected != 0 {
		t.Errorf("signed declarations were not stored: attributions %d, report %+v", len(as), rep)
	}
}

// 두 모드의 차이를 같은 입력으로 잰다. 기존 목록 모드(필수 아님)는 지금과 같다.
func TestBoundAndLegacyModesDiffer(t *testing.T) {
	k, kPriv, _ := sign.Generate()

	unsigned := func() *discoveryv1.CollectionResult {
		r := opensslResult("web-01", "libssl.so.3")
		r.Envelope.CollectorId = "openssl-collector"
		return r
	}
	unsignedAttr := func() *discoveryv1.CollectionResult {
		rs, _ := declaration.ImportAttributionCSV(strings.NewReader("web-01,10.0.0.9:443,billing\n"))
		return rs[0]
	}
	otherID := func() *discoveryv1.CollectionResult {
		return signAs(t, opensslResult("web-01", "libssl.so.3"), "jvm-collector", kPriv)
	}

	type got struct{ accepted, unverified, rejected, attributions int }
	run := func(o ingest.IngestOptions, store *history.MemStore, in *discoveryv1.CollectionResult) got {
		rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{in}, o)
		if err != nil {
			t.Fatal(err)
		}
		as, _ := store.Attributions()
		return got{rep.Accepted, rep.Unverified, rep.Rejected, len(as)}
	}
	for _, c := range []struct {
		name          string
		in            func() *discoveryv1.CollectionResult
		legacy, bound got
	}{
		{"unsigned result", unsigned, got{0, 0, 1, 0}, got{0, 0, 1, 0}},
		{"unsigned app declaration", unsignedAttr, got{0, 0, 0, 1}, got{0, 0, 1, 0}},
		{"another collector ID", otherID, got{1, 0, 0, 0}, got{0, 0, 1, 0}},
	} {
		// 서명 없는 결과는 기존 목록 모드에서도 키가 있으면 검증 실패다. 차이는 선언과 다른 ID에서 난다.
		ls := history.NewMemStore()
		lo := legacyOpts(ls, []string{k})
		if g := run(lo, ls, c.in()); g != c.legacy {
			t.Errorf("%s, legacy mode: %+v, want %+v", c.name, g, c.legacy)
		}
		bs := history.NewMemStore()
		if g := run(boundOpts(bs, map[string][]string{"openssl-collector": {k}}), bs, c.in()); g != c.bound {
			t.Errorf("%s, bound mode: %+v, want %+v", c.name, g, c.bound)
		}
	}
}

// 결합 모드는 다른 ID의 키로 다시 시도하지 않는다. 같은 ID에 옛 키·새 키가 함께 있으면 둘 다 통과한다.
func TestBoundNoFallbackAndRotation(t *testing.T) {
	k, kPriv, _ := sign.Generate()
	k2, k2Priv, _ := sign.Generate()

	store := history.NewMemStore()
	rep, _ := ingest.IngestWith([]*discoveryv1.CollectionResult{signAs(t, opensslResult("web-01", "a"), "network-collector", kPriv)},
		boundOpts(store, map[string][]string{"openssl-collector": {k}, "network-collector": {k2}}))
	if rep.Rejected != 1 || snapshots(t, store, "web-01") != 0 {
		t.Errorf("it fell back to another ID's key: %+v", rep)
	}

	rot := map[string][]string{"openssl-collector": {k, k2}}
	store = history.NewMemStore()
	rep, _ = ingest.IngestWith([]*discoveryv1.CollectionResult{
		signAs(t, opensslResult("web-01", "a"), "openssl-collector", kPriv),
		signAs(t, opensslResult("web-02", "a"), "openssl-collector", k2Priv),
	}, boundOpts(store, rot))
	if rep.Accepted != 2 || rep.Rejected != 0 {
		t.Errorf("rotation: %+v", rep)
	}
}

// 두 검증을 함께 주면 어느 쪽인지 정하지 않고 멈춘다.
func TestBothVerifiersRefused(t *testing.T) {
	o := boundOpts(history.NewMemStore(), nil)
	o.VerifySig = func(*discoveryv1.CollectionResult) bool { return true }
	if _, err := ingest.IngestWith([]*discoveryv1.CollectionResult{res("web-01")}, o); err == nil {
		t.Error("both verifiers were accepted")
	}
}

// 결합 모드에서는 서명 검증을 통과한 결과만 노드 식별 검사에 넣는다. 정상 결과와, 같은 노드 ID에 다른 머신 지문을
// 담았지만 서명이 거부되는 결과를 한 번에 적재한다. 정상 결과는 저장되고, 거부된 결과에는 서명 거부 기록만 남고,
// 노드 식별 충돌은 없다.
func TestBoundRejectedResultMakesNoIdentityConflict(t *testing.T) {
	k, kPriv, _ := sign.Generate()
	_, otherPriv, _ := sign.Generate()
	keys := map[string][]string{"openssl-collector": {k}}

	good := opensslResult("web-01", "libssl.so.3")
	good.Envelope.Machine = &commonv1.MachineIdentity{MachineId: "machine-a"}
	signAs(t, good, "openssl-collector", kPriv)
	forged := opensslResult("web-01", "libssl.so.3")
	forged.Envelope.Machine = &commonv1.MachineIdentity{MachineId: "machine-b"}
	signAs(t, forged, "openssl-collector", otherPriv)

	store := history.NewMemStore()
	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{good, forged}, boundOpts(store, keys))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accepted != 1 || rep.Rejected != 1 || snapshots(t, store, "web-01") != 1 {
		t.Errorf("the good result was not stored alone: %+v", rep)
	}
	if len(rep.Conflicts) != 0 {
		t.Errorf("a rejected result made an identity conflict: %+v", rep.Conflicts)
	}
	rs, _ := store.Rejections(0)
	if len(rs) != 1 || rs[0].Kind != history.RejectSignature {
		t.Errorf("rejections: %+v", rs)
	}
}
