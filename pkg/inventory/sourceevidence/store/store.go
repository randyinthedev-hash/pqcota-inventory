// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package store — 소스 근거의 원본·설정·변환 결과·수신 기록을 조직 단위로 보관한다(설계 v2.1 §6).
//
// 런타임 스냅샷과 테이블을 나눈다. 여기에 쓰는 것은 스냅샷을 만들지 않고 노드의 최신 상태를 바꾸지 않는다.
//
// 넷을 한 트랜잭션으로 쓴다.
//   - 원본: 받은 바이트 그대로와 SHA-256. 같은 해시면 한 번만 둔다.
//   - 설정: 변환에 쓴 매핑 설정(프리셋·사용자)의 원문. 같은 해시면 한 번만 둔다.
//   - 변환 결과: 불변. 같은 ID에 다른 내용이 오면 [ErrImmutable]로 거부한다 — 덮어쓰지 않는다.
//   - 수신 기록: 받을 때마다 한 줄. 재수신은 새 내용이 아니라 수신 기록으로만 남는다.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
)

// ErrImmutable — 같은 변환 결과 ID에 저장된 것과 다른 내용이 왔다. 변환기가 같은 판에서 동작을 바꿨다는
// 뜻이므로 조용히 넘기지 않는다.
var ErrImmutable = errors.New("source evidence interpretation is immutable: stored content differs for the same id")

// ErrMismatch — 저장 요청이 스스로 맞지 않는다(원본 해시·결과 ID).
var ErrMismatch = errors.New("source evidence does not match its input")

// Input — 받은 원본 하나와 변환에 쓴 설정 원문.
type Input struct {
	NodeID string // 대상 노드. 비어 있으면 지정하지 않은 것이다
	Raw    []byte
	Maps   []MapInput // 변환 결과의 Maps와 같은 것(순서 무관). 설정 없이 변환했으면 비운다
}

// MapInput — 설정 원문 하나. 결과는 원문 해시로 가리킨다.
type MapInput struct {
	Source string // "preset" 또는 "user"
	Raw    []byte
}

// MapsOf — 변환에 쓴 설정을 저장 입력으로.
func MapsOf(lms []*sourceevidence.LoadedMap) []MapInput {
	out := make([]MapInput, len(lms))
	for i, lm := range lms {
		out[i] = MapInput{Source: lm.Source(), Raw: lm.Raw()}
	}
	return out
}

// Receipt — 한 번 받은 기록. 새 내용이 생겼는지를 함께 적는다.
type Receipt struct {
	Seq               int64     `json:"seq"`
	NodeID            string    `json:"nodeId"`
	InputSHA256       string    `json:"inputSha256"`
	InterpretationID  string    `json:"interpretationId"`
	NewInput          bool      `json:"newInput"`
	NewInterpretation bool      `json:"newInterpretation"`
	ReceivedAt        time.Time `json:"receivedAt"`
}

// Summary — 목록용. 본문(항목·위치)을 풀지 않고 보여 줄 것만.
type Summary struct {
	ID               string                   `json:"id"`
	InputSHA256      string                   `json:"inputSha256"`
	SpecVersion      string                   `json:"specVersion"`
	SchemaVersion    string                   `json:"schemaVersion"`
	ConverterVersion string                   `json:"converterVersion"`
	Rules            []sourceevidence.RuleRef `json:"rules"`
	Maps             []sourceevidence.MapRef  `json:"maps"`
	Counts           sourceevidence.Counts    `json:"counts"`
	Producer         []sourceevidence.Field   `json:"producer"`
	CreatedAt        time.Time                `json:"createdAt"`
}

// Store — 조직에 묶인 소스 근거 저장소. 조직을 바꾸는 방법은 없다(history와 같은 규칙).
type Store interface {
	// Save — 원본·변환 결과·수신 기록을 한 트랜잭션으로 쓴다. 실패하면 아무것도 남지 않는다.
	Save(in Input, interp *sourceevidence.Interpretation) (Receipt, error)
	// Interpretations — 최근 것부터. limit<=0이면 100건.
	Interpretations(limit int) ([]Summary, error)
	// Interpretation — 없으면 nil, nil.
	Interpretation(id string) (*sourceevidence.Interpretation, error)
	// InputRaw — 원본 바이트. 없으면 nil, nil.
	InputRaw(sha256Hex string) ([]byte, error)
	// MapRaw — 설정 원문. 없으면 nil, nil.
	MapRaw(sha256Hex string) ([]byte, error)
	// Receipts — 최근 것부터. limit<=0이면 100건.
	Receipts(limit int) ([]Receipt, error)
	// ReceiptsOf — 한 변환 결과의 수신 기록, 최근 것부터. limit<=0이면 100건.
	ReceiptsOf(interpretationID string, limit int) ([]Receipt, error)
}

const defaultLimit = 100

// prepared — 저장 전에 한 번 계산해 두는 값. 두 구현이 같은 검사를 거친다.
type prepared struct {
	inputSHA string
	maps     []preparedMap
	body     []byte // 변환 결과 JSON(결정론적)
	bodySHA  string
	summary  Summary
}

func prepare(in Input, interp *sourceevidence.Interpretation) (prepared, error) {
	if interp == nil {
		return prepared{}, fmt.Errorf("%w: no interpretation", ErrMismatch)
	}
	sum := sha256.Sum256(in.Raw)
	inSHA := hex.EncodeToString(sum[:])
	if interp.InputSHA256 != inSHA {
		return prepared{}, fmt.Errorf("%w: interpretation was made from input %s, not %s", ErrMismatch, interp.InputSHA256, inSHA)
	}
	if !interp.IDMatches() {
		return prepared{}, fmt.Errorf("%w: interpretation id %s does not match its rules and versions", ErrMismatch, interp.ID)
	}
	maps, err := prepareMaps(in.Maps, interp.Maps)
	if err != nil {
		return prepared{}, err
	}
	body, err := json.Marshal(interp)
	if err != nil {
		return prepared{}, err
	}
	bs := sha256.Sum256(body)
	return prepared{
		inputSHA: inSHA,
		maps:     maps,
		body:     body,
		bodySHA:  hex.EncodeToString(bs[:]),
		summary:  summaryOf(interp),
	}, nil
}

// summaryOf — 목록 요약. 슬라이스·맵을 interp와 함께 쓴다 — 오래 붙잡아 둘 값이면 저장한 JSON에서 다시
// 만든 interp로 부른다(MemStore가 그렇게 한다).
func summaryOf(interp *sourceevidence.Interpretation) Summary {
	return Summary{
		ID: interp.ID, InputSHA256: interp.InputSHA256, SpecVersion: interp.SpecVersion,
		SchemaVersion: interp.SchemaVersion, ConverterVersion: interp.ConverterVersion,
		Rules: interp.Rules, Maps: interp.Maps, Counts: interp.Counts, Producer: interp.Producer,
	}
}

type preparedMap struct {
	ref sourceevidence.MapRef
	raw []byte
}

// prepareMaps — 결과가 가리키는 설정마다 원문이 하나씩 있어야 한다. 원문 없이 결과만 저장하면 어느 설정으로 읽었는지
// 되짚을 수 없고, 결과에 없는 원문을 저장하면 쓰지 않은 설정이 남는다.
func prepareMaps(given []MapInput, refs []sourceevidence.MapRef) ([]preparedMap, error) {
	bySHA := map[string]MapInput{}
	for _, g := range given {
		s := sha256.Sum256(g.Raw)
		bySHA[hex.EncodeToString(s[:])] = g
	}
	if len(bySHA) != len(given) || len(given) != len(refs) {
		return nil, fmt.Errorf("%w: %d maps given for an interpretation that used %d", ErrMismatch, len(given), len(refs))
	}
	out := make([]preparedMap, 0, len(refs))
	for _, r := range refs {
		g, ok := bySHA[r.SHA256]
		if !ok {
			return nil, fmt.Errorf("%w: the raw map %s (%s) was not given", ErrMismatch, r.SHA256, r.ID)
		}
		if g.Source != r.Source {
			return nil, fmt.Errorf("%w: map %s is %s in the interpretation, %s in the input", ErrMismatch, r.ID, r.Source, g.Source)
		}
		out = append(out, preparedMap{ref: r, raw: g.Raw})
	}
	return out, nil
}

func decodeInterpretation(body []byte) (*sourceevidence.Interpretation, error) {
	var out sourceevidence.Interpretation
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
