// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

// Package history — append-only 디스커버리 이력(규정서 §2.4⑥, §1.2 원본 불변).
// MemStore(인메모리, 테스트·단일 실행) + PgStore(Postgres 영속화)를 제공한다.
package history

import (
	"sort"
	"sync"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
)

// Snapshot — 디스커버리 상태 스냅샷. 노드별 파생 Finding + 완전성 맵.
// 파생 뷰이므로 어떤 규칙 버전으로 만들어졌는지(RulesetVersion) 함께 보관해 재현 가능(§1.2).
type Snapshot struct {
	// Seq·CreatedAt은 적재 시 저장소가 부여한다(호출자가 채우지 않는다). 이력의 시간축 —
	// 이게 없으면 append-only로 쌓아도 "언제 무엇을 봤나"를 되짚을 수 없다.
	Seq            int64
	ID             string
	NodeID         string
	Findings       []*discoveryv1.Finding
	Edges          []*discoveryv1.ObservedEdge // 통신 엣지 관측 레인(인벤토리 설계 §6, network-collector). 노드 내부 자산과 별도.
	Completeness   *commonv1.Completeness
	RulesetVersion string
	CreatedAt      time.Time

	// ExcludedByScope — 자산 스코프 정책으로 **관리 대상에서 뺀** finding 수.
	// 알리지 않고 0으로 두면 인벤토리가 "그런 자산은 없다"고 거짓말한다 — 제외는 부재가 아니므로
	// 반드시 세어서 뷰가 고지한다(§2.6).
	ExcludedByScope int

	// Created — 이번 Append가 **새 스냅샷을 만들었는지**. false면 실질 내용이 직전과 같아
	// 기존 스냅샷을 재확인한 것이며, ID·Seq·CreatedAt은 그 기존 스냅샷의 값으로 바뀐다
	// (관측 사실 자체는 관측 기록에 언제나 남는다).
	Created bool
}

// ObsStat — 한 스냅샷이 몇 번·언제 관측됐는지. 스냅샷은 변화 시에만 쌓이므로,
// "매일 스캔했다"는 증거는 이쪽에 남는다.
type ObsStat struct {
	Count int
	First time.Time
	Last  time.Time
}

// Store — append-only 히스토리. 원본은 절대 in-place 수정하지 않는다(§1.2). 2층 구조는 인벤토리 설계 §7.2.
//
// 두 층으로 나뉜다:
//   - **스냅샷**(무거움) — 실질 내용이 **바뀔 때만** 쌓인다. 변화 추적·재계산 재현의 근거.
//   - **관측 기록**(가벼움) — 적재할 때마다 1건. "언제 봤나"(관측 증명)의 근거.
//
// 같은 상태를 반복 관측해도 스냅샷은 늘지 않으므로, 무거운 저장은 **변화 횟수만큼만** 자란다.
type Store interface {
	// Append — 관측 1건을 기록한다. 실질 내용이 직전과 같으면 스냅샷을 새로 만들지 않고
	// 기존 것을 가리킨다. 적재 후 s.Seq·s.CreatedAt·s.Created를 저장소가 채워 넣는다.
	Append(*Snapshot) error
	Snapshots(nodeID string) ([]*Snapshot, error)
	Latest(nodeID string) (*Snapshot, error)
	ByID(id string) (*Snapshot, error) // 스냅샷 단건(이력 상세·diff용). 없으면 (nil, nil).
	Nodes() ([]string, error)          // 스냅샷을 가진 전 노드 ID(인벤토리 뷰가 "전체"를 훑기 위함)
	// ObservationStats — 노드의 스냅샷별 관측 요약(스냅샷 id → 횟수·첫·마지막).
	ObservationStats(nodeID string) (map[string]ObsStat, error)
}

// SnapshotLookup — 참조로 스냅샷을 찾는 좁은 조회. **Store와 별개다.** Store를 넓히면 그것을
// 구현한 외부 코드가 깨진다. 이 리포는 부가 기능을 별도 인터페이스로 갈라 왔다.
//
// 참조의 **형식**은 모른다 — 그것은 프로비저닝 계약(SnapshotReference)의 일이고, 이력 계층이
// 하류 계약을 알면 안 된다. 여기는 키로만 찾는다. 두 저장소(Postgres·메모리)가 구현한다.
type SnapshotLookup interface {
	ByID(id string) (*Snapshot, error)
	// ByContentHashV1 — (org, node, ruleset, digest). org는 핸들이 든다. 없으면 (nil, nil).
	// ruleset이 지문 안에도 들어 있어 조건이 겹치지만, 참조가 규칙 판을 밝히면 못 찾았을 때
	// 「규칙 판이 다르다」를 추측이 아니라 값으로 말할 수 있다.
	ByContentHashV1(node, ruleset, digest string) (*Snapshot, error)
}

// MemStore — 인메모리 append-only 구현(테스트·단일 실행용). 영속화는 PgStore.
//
// **PgStore와 같은 규칙으로 조직에 묶인다.** 한 MemStore는 한 조직만 담는다 — 테스트가 격리 없는
// 경로를 타면 실제와 어긋나기 때문이다.
type MemStore struct {
	org    org.ID
	mu     sync.RWMutex
	seq    int64 // PgStore의 BIGSERIAL에 대응 — 전역 단조증가
	byNode map[string][]*Snapshot
	hash   map[string]string              // 스냅샷 id → 내용 지문(중복 억제, 옛 규칙)
	hashV1 map[string]string              // 스냅샷 id → 참조용 지문(v1). **접는 기준**
	obs    map[string]map[string]*ObsStat // node → 스냅샷 id → 관측 요약
	events []RetentionEvent               // 절단 기록(보존 정책 집행 흔적)
	rej    memRejections                  // 거절 기록(받지 않은 사실)
	attr   memAttributions                // 사람이 선언한 앱(스냅샷 타임라인 밖)
}

// NewMemStore — 조직을 대지 않고 연다. org.Default에 묶인다(시그니처를 바꾸지 않는다 —
// docs/compatibility.md §3).
func NewMemStore() *MemStore { m, _ := NewMemStoreIn(""); return m }

// NewMemStoreIn — 조직에 묶인 인메모리 저장소. 규칙은 NewPgStoreIn과 같다.
func NewMemStoreIn(organization string) (*MemStore, error) {
	o, err := org.Resolve(organization)
	if err != nil {
		return nil, err
	}
	return newMem(o), nil
}

// Org — 이 저장소가 묶인 조직.
func (m *MemStore) Org() org.ID { return m.org }

func newMem(o org.ID) *MemStore {
	return &MemStore{
		org:    o,
		byNode: make(map[string][]*Snapshot),
		hash:   make(map[string]string),
		hashV1: make(map[string]string),
		obs:    make(map[string]map[string]*ObsStat),
	}
}

func (m *MemStore) Append(s *Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()

	// 실질 내용이 직전과 같으면 스냅샷을 새로 만들지 않는다 — 관측 사실만 기록.
	// **v1 지문으로 접는다.** 옛 지문(ContentHash)으로 접으면 v1이 없는 옛 행이 재사용되어
	// v1 참조가 영원히 찾히지 않는다. v1이 빈 옛 행은 같은 행이 아니다 — 새 행을 만든다.
	if prev := m.latestLocked(s.NodeID); prev != nil && m.hashV1[prev.ID] != "" && m.hashV1[prev.ID] == ContentHashV1(s) {
		s.ID, s.Seq, s.CreatedAt, s.Created = prev.ID, prev.Seq, prev.CreatedAt, false
		m.observeLocked(s.NodeID, prev.ID, now)
		return nil
	}

	m.seq++
	s.Seq = m.seq
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.Created = true
	m.hash[s.ID] = ContentHash(s)
	m.hashV1[s.ID] = ContentHashV1(s)
	m.byNode[s.NodeID] = append(m.byNode[s.NodeID], s)
	m.observeLocked(s.NodeID, s.ID, now)
	return nil
}

func (m *MemStore) latestLocked(nodeID string) *Snapshot {
	if s := m.byNode[nodeID]; len(s) > 0 {
		return s[len(s)-1]
	}
	return nil
}

func (m *MemStore) observeLocked(nodeID, snapID string, at time.Time) {
	if m.obs[nodeID] == nil {
		m.obs[nodeID] = make(map[string]*ObsStat)
	}
	st := m.obs[nodeID][snapID]
	if st == nil {
		st = &ObsStat{First: at}
		m.obs[nodeID][snapID] = st
	}
	st.Count++
	st.Last = at
}

func (m *MemStore) ObservationStats(nodeID string) (map[string]ObsStat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]ObsStat, len(m.obs[nodeID]))
	for id, st := range m.obs[nodeID] {
		out[id] = *st
	}
	return out, nil
}

// ByID — 전 노드를 훑어 스냅샷 id로 찾는다(id는 전역 유일 전제).
func (m *MemStore) ByID(id string) (*Snapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, snaps := range m.byNode {
		for _, s := range snaps {
			if s.ID == id {
				return s, nil
			}
		}
	}
	return nil, nil
}

func (m *MemStore) ByContentHashV1(node, ruleset, digest string) (*Snapshot, error) {
	if digest == "" {
		return nil, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	snaps := m.byNode[node]
	// 최근 것부터 — 같은 상태를 두 행이 가질 수 있다(이행의 자국, D8). 뒤의 것이 지금 규칙의 것이다.
	for i := len(snaps) - 1; i >= 0; i-- {
		s := snaps[i]
		if s.RulesetVersion == ruleset && m.hashV1[s.ID] == digest {
			return s, nil
		}
	}
	return nil, nil
}

func (m *MemStore) Snapshots(nodeID string) ([]*Snapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	src := m.byNode[nodeID]
	out := make([]*Snapshot, len(src))
	copy(out, src)
	return out, nil
}

func (m *MemStore) Latest(nodeID string) (*Snapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s := m.byNode[nodeID]; len(s) > 0 {
		return s[len(s)-1], nil
	}
	return nil, nil
}

func (m *MemStore) Nodes() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.byNode))
	for n := range m.byNode {
		out = append(out, n)
	}
	sort.Strings(out) // 결정론적 순서
	return out, nil
}
