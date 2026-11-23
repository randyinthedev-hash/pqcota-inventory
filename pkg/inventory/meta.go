// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"sort"
	"sync"

	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
)

// MetaStore — 머신 메타데이터(엔드포인트·프로필) 저장소. 히스토리(append-only)와 달리 **upsert**한다
// — 엔드포인트·프로필은 사용자가 재사용·수정하는 가변 메타데이터(인벤토리 설계 §2.0). 접근 비밀은 담기지 않는다.
type MetaStore interface {
	UpsertEndpoint(*inventoryv1.MachineEndpoint) error
	UpsertProfile(*inventoryv1.MachineProfile) error
	Endpoint(nodeID string) (*inventoryv1.MachineEndpoint, error)
	Profile(nodeID string) (*inventoryv1.MachineProfile, error)
}

// EndpointLister — 등록된 엔드포인트 전부. **MetaStore와 별개다.** MetaStore를 넓히면 그것을 구현한 외부 코드가
// 깨진다(SnapshotLookup과 같은 이유). 토폴로지가 관측된 상대 IP를 등록 노드로 이을 때 쓴다 — IP가 한 노드에만
// 대응하는지 알려면 목록 전체가 필요하다. node_id 순서로 돌려준다.
type EndpointLister interface {
	Endpoints() ([]*inventoryv1.MachineEndpoint, error)
}

// MemMetaStore — 인메모리 구현(테스트·단일 실행).
//
// **PgMetaStore와 같은 규칙으로 조직에 묶인다.** 한 저장소는 한 조직만 담는다 — Pg판만 조직을
// 갖고 Mem판이 안 가지면 테스트가 실제에 없는 경로를 타게 된다.
type MemMetaStore struct {
	mu   sync.RWMutex
	org  org.ID
	ep   map[string]*inventoryv1.MachineEndpoint
	prof map[string]*inventoryv1.MachineProfile
}

// NewMemMetaStore — 조직을 대지 않고 연다(org.Default). 시그니처를 바꾸지 않는다.
func NewMemMetaStore() *MemMetaStore { m, _ := NewMemMetaStoreIn(""); return m }

// NewMemMetaStoreIn — 조직에 묶인 인메모리 메타 저장소. 규칙은 NewPgMetaStoreIn과 같다.
func NewMemMetaStoreIn(organization string) (*MemMetaStore, error) {
	o, err := org.Resolve(organization)
	if err != nil {
		return nil, err
	}
	return &MemMetaStore{org: o, ep: map[string]*inventoryv1.MachineEndpoint{}, prof: map[string]*inventoryv1.MachineProfile{}}, nil
}

// Org — 이 저장소가 묶인 조직(org.Scoped).
func (m *MemMetaStore) Org() org.ID { return m.org }

func (m *MemMetaStore) UpsertEndpoint(e *inventoryv1.MachineEndpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ep[e.GetNodeId()] = e
	return nil
}

// Endpoints — EndpointLister. node_id 순서.
func (m *MemMetaStore) Endpoints() ([]*inventoryv1.MachineEndpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*inventoryv1.MachineEndpoint, 0, len(m.ep))
	for _, e := range m.ep {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetNodeId() < out[j].GetNodeId() })
	return out, nil
}

func (m *MemMetaStore) UpsertProfile(p *inventoryv1.MachineProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prof[p.GetNodeId()] = p
	return nil
}

func (m *MemMetaStore) Endpoint(nodeID string) (*inventoryv1.MachineEndpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ep[nodeID], nil
}

func (m *MemMetaStore) Profile(nodeID string) (*inventoryv1.MachineProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.prof[nodeID], nil
}
