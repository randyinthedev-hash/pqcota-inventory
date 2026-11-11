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
	interps  map[string]memInterp
	order    []string // 변환 결과 ID, 저장 순서
	receipts []Receipt
}

type memInterp struct {
	body    []byte
	bodySHA string
	summary Summary
}

// NewMemStoreIn — organization이 비면 org.Resolve의 규칙을 따른다.
func NewMemStoreIn(organization string) (*MemStore, error) {
	o, err := org.Resolve(organization)
	if err != nil {
		return nil, err
	}
	return &MemStore{org: o, inputs: map[string][]byte{}, interps: map[string]memInterp{}}, nil
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
	if _, ok := m.interps[p.summary.ID]; !ok {
		s := p.summary
		s.CreatedAt = now
		m.interps[s.ID] = memInterp{body: p.body, bodySHA: p.bodySHA, summary: s}
		m.order = append(m.order, s.ID)
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
		out = append(out, m.interps[m.order[i]].summary)
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

func (m *MemStore) InputRaw(sha string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.inputs[sha]
	if !ok {
		return nil, nil
	}
	return bytes.Clone(b), nil
}

func (m *MemStore) Receipts(limit int) ([]Receipt, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Receipt
	for i := len(m.receipts) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.receipts[i])
	}
	return out, nil
}
