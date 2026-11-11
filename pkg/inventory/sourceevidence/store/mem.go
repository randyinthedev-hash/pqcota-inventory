// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
)

// MemStore — 인메모리 구현(테스트·미리보기용). 한 MemStore는 한 조직만 담는다.
type MemStore struct {
	org      org.ID
	mu       sync.Mutex
	inputs   map[string][]byte // sha → 원본
	maps     map[string][]byte // sha → 설정 원문
	interps  map[string]memInterp
	order    []string // 변환 결과 ID, 저장 순서
	receipts []Receipt
}

// memInterp — 저장한 JSON 바이트만 쥔다. 목록과 상세가 모두 여기서 다시 만들어지므로 둘이 어긋나지 않고,
// 호출자가 넘긴 값이나 받아 간 값을 고쳐도 저장된 것은 바뀌지 않는다.
type memInterp struct {
	body      []byte
	bodySHA   string
	createdAt time.Time
}

// NewMemStoreIn — organization이 비면 org.Resolve의 규칙을 따른다.
func NewMemStoreIn(organization string) (*MemStore, error) {
	o, err := org.Resolve(organization)
	if err != nil {
		return nil, err
	}
	return &MemStore{org: o, inputs: map[string][]byte{}, maps: map[string][]byte{}, interps: map[string]memInterp{}}, nil
}

// Org — 이 저장소가 묶인 조직.
func (m *MemStore) Org() org.ID { return m.org }

// Save — 검사를 모두 마친 뒤에만 쓴다. 중간에 실패하면 아무것도 바뀌지 않는다(Pg의 트랜잭션과 같은 결과).
func (m *MemStore) Save(in Input, interp *sourceevidence.Interpretation) (Receipt, error) {
	p, err := prepare(in, interp)
	if err != nil {
		return Receipt{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.interps[p.summary.ID]; ok && old.bodySHA != p.bodySHA {
		return Receipt{}, fmt.Errorf("%w: %s", ErrImmutable, p.summary.ID)
	}
	now := time.Now().UTC()
	r := Receipt{NodeID: in.NodeID, InputSHA256: p.inputSHA, InterpretationID: p.summary.ID, ReceivedAt: now}
	if _, ok := m.inputs[p.inputSHA]; !ok {
		m.inputs[p.inputSHA] = bytes.Clone(in.Raw)
		r.NewInput = true
	}
	for _, pm := range p.maps {
		if _, ok := m.maps[pm.ref.SHA256]; !ok {
			m.maps[pm.ref.SHA256] = bytes.Clone(pm.raw)
		}
	}
	if _, ok := m.interps[p.summary.ID]; !ok {
		m.interps[p.summary.ID] = memInterp{body: p.body, bodySHA: p.bodySHA, createdAt: now}
		m.order = append(m.order, p.summary.ID)
		r.NewInterpretation = true
	}
	r.Seq = int64(len(m.receipts)) + 1
	m.receipts = append(m.receipts, r)
	return r, nil
}

func (m *MemStore) Interpretations(limit int) ([]Summary, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Summary
	for i := len(m.order) - 1; i >= 0 && len(out) < limit; i-- {
		it := m.interps[m.order[i]]
		interp, err := decodeInterpretation(it.body)
		if err != nil {
			return nil, err
		}
		s := summaryOf(interp)
		s.CreatedAt = it.createdAt
		out = append(out, s)
	}
	return out, nil
}

func (m *MemStore) Interpretation(id string) (*sourceevidence.Interpretation, error) {
	m.mu.Lock()
	it, ok := m.interps[id]
	m.mu.Unlock()
	if !ok {
		return nil, nil
	}
	return decodeInterpretation(it.body)
}

func (m *MemStore) MapRaw(sha string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.maps[sha]
	if !ok {
		return nil, nil
	}
	return bytes.Clone(b), nil
}

func (m *MemStore) InputRaw(sha string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.inputs[sha]
	if !ok {
		return nil, nil
	}
	return bytes.Clone(b), nil
}

func (m *MemStore) Receipts(limit int) ([]Receipt, error) { return m.receiptsWhere("", limit) }

func (m *MemStore) ReceiptsOf(id string, limit int) ([]Receipt, error) {
	if id == "" {
		return nil, nil
	}
	return m.receiptsWhere(id, limit)
}

// receiptsWhere — id가 비면 전부. Receipt에는 슬라이스·맵이 없어 값 복사로 충분하다.
func (m *MemStore) receiptsWhere(id string, limit int) ([]Receipt, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Receipt
	for i := len(m.receipts) - 1; i >= 0 && len(out) < limit; i-- {
		if id == "" || m.receipts[i].InterpretationID == id {
			out = append(out, m.receipts[i])
		}
	}
	return out, nil
}
