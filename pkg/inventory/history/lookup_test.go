// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"fmt"
	"testing"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// 내부 테스트다 — 옛 행(v1 지문이 없는 행)을 흉내 내려면 hashV1을 비워야 하는데, 그것은
// 밖에서 할 수 없다.

var seqID int

// 실제 적재는 시각을 붙여 id를 짓는다 — 같은 내용이라도 id는 매번 다르다.
func snapV(node, ruleset, alg string) *Snapshot {
	seqID++
	return &Snapshot{
		ID: fmt.Sprintf("s-%d", seqID), NodeID: node, RulesetVersion: ruleset,
		Findings: []*discoveryv1.Finding{{Id: "f1", Algorithm: alg}},
	}
}

// ★ 중복 억제는 v1로 접는다. 옛 지문(ContentHash)이 같아도 규칙 판이나 제외 수가 다르면 다른
// 상태이고, v1이 없는 옛 행은 같은 행이 아니다 — 새 행을 만든다. 옛 지문으로 계속 접으면
// 업그레이드 뒤에도 v1 열이 영원히 비어 v1 참조를 찾지 못한다.
func TestDedupFoldsOnV1NotOnLegacyHash(t *testing.T) {
	m := NewMemStore()

	// 같은 내용을 두 번 — 접힌다.
	a := snapV("n", "pqcota-enrich/v2", "X25519")
	b := snapV("n", "pqcota-enrich/v2", "X25519")
	_ = m.Append(a)
	_ = m.Append(b)
	if b.Created || b.ID != a.ID {
		t.Fatal("같은 상태를 다시 적재했는데 접히지 않았다")
	}

	// 같은 내용, 다른 규칙 판 — 옛 지문은 같지만 v1은 다르다. 접히면 안 된다.
	c := snapV("n", "pqcota-enrich/v3", "X25519")
	_ = m.Append(c)
	if !c.Created {
		t.Fatal("규칙 판이 다른데 옛 지문이 같다고 접혔다")
	}

	// 옛 행을 흉내 낸다: 직전 행의 v1을 지운다. 같은 내용이 오면 재사용하지 않고 새 행이어야 한다.
	m.hashV1[c.ID] = ""
	d := snapV("n", "pqcota-enrich/v3", "X25519")
	_ = m.Append(d)
	if !d.Created || d.ID == c.ID {
		t.Fatal("v1 이 없는 옛 행을 재사용했다 — v1 참조가 영원히 찾히지 않는다")
	}
}

// 조회 키 (node, ruleset, digest)가 인터페이스와 같다. 규칙 판이 다르면 못 찾고, 같은 상태가 두
// 행일 때(이행의 자국) 최근 것을 돌려준다.
func TestByContentHashV1(t *testing.T) {
	m := NewMemStore()
	var _ SnapshotLookup = m

	s := snapV("n", "pqcota-enrich/v2", "X25519")
	_ = m.Append(s)
	digest := ContentHashV1(s)

	got, err := m.ByContentHashV1("n", "pqcota-enrich/v2", digest)
	if err != nil || got == nil || got.ID != s.ID {
		t.Fatalf("찾지 못했다: %v %v", got, err)
	}
	if got, _ := m.ByContentHashV1("n", "pqcota-enrich/v1", digest); got != nil {
		t.Error("규칙 판이 다른데 찾았다")
	}
	if got, _ := m.ByContentHashV1("other", "pqcota-enrich/v2", digest); got != nil {
		t.Error("다른 노드에서 찾았다")
	}
	if got, _ := m.ByContentHashV1("n", "pqcota-enrich/v2", ""); got != nil {
		t.Error("빈 지문으로 찾았다")
	}
}
