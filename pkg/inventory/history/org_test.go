// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"errors"
	"testing"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
)

// TestStoreIsBoundToAnOrg — 저장소를 열면 반드시 어떤 조직에 묶인다. 안 묶인 저장소는 만들 수 없다.
//
// 조직이 없는 핸들을 만들 수 있으면 그 핸들이 쓴 행은 나중에 누구 것인지 알 수 없다.
func TestStoreIsBoundToAnOrg(t *testing.T) {
	if got := NewMemStore().Org(); got != org.Default {
		t.Fatalf("a store opened without an organization was bound to %q — it must be org.Default", got)
	}
	m, err := NewMemStoreIn("acme")
	if err != nil || m.Org() != org.ID("acme") {
		t.Fatalf("it was opened with an organization named, yet %q %v", m.Org(), err)
	}
	if _, err := NewMemStoreIn("Acme"); err == nil {
		t.Fatal("a malformed organization was accepted — a typo silently becomes a different organization")
	}
}

// TestRequiredModeRefusesTheDefaultStore — 여럿을 담는 배포에서 조직 없는 저장소는 열리지 않는다.
//
// 데이터가 섞인 뒤에는 되돌릴 수 없으므로, 쓰는 자리가 아니라 **여는 자리**에서 막는다.
func TestRequiredModeRefusesTheDefaultStore(t *testing.T) {
	t.Setenv(org.RequireEnv, "1")
	if _, err := NewMemStoreIn(""); !errors.Is(err, org.ErrDefaultNotAllowed) {
		t.Fatalf("in required mode a store opened without an organization: %v", err)
	}
}

// TestOrgsDoNotSeeEachOther — 같은 node_id를 쓰는 두 조직이 서로의 이력을 보지 않는다.
//
// `web-01` 충돌은 예외가 아니라 기본값에 가깝다 — node_id는 고객 CMDB ID·FQDN·machine-id 파생
// self-id이기 때문이다. 섞이면 한 노드의 이력으로 **병합되어** 되돌릴 수 없다.
func TestOrgsDoNotSeeEachOther(t *testing.T) {
	a, err := NewMemStoreIn("acme")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewMemStoreIn("beta")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Append(&Snapshot{ID: "snap-a", NodeID: "web-01", RulesetVersion: "r1"}); err != nil {
		t.Fatal(err)
	}

	if nodes, _ := b.Nodes(); len(nodes) != 0 {
		t.Fatalf("nodes of another organization are visible: %v", nodes)
	}
	if s, _ := b.ByID("snap-a"); s != nil {
		t.Fatal("knowing the id alone opens someone else's snapshot")
	}
	if s, _ := b.Latest("web-01"); s != nil {
		t.Fatal("the same node_id exposes someone else's latest snapshot")
	}
	if nodes, _ := a.Nodes(); len(nodes) != 1 {
		t.Fatalf("nodes of the own organization are not visible: %v", nodes)
	}
}
