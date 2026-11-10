// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sourceevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Limits — 작은 입력이 큰 결과로 불어나는 것을 막는다. 넘으면 변환을 거부한다(부분 결과를 내지 않는다).
// 기본값은 검토 시작값이다(설계 §6). 원본 크기 상한은 읽기 전에 CLI가 건다.
type Limits struct {
	MaxComponents       int
	MaxLocationsPerItem int
	MaxDepth            int // 중첩 components 깊이
}

// DefaultLimits — 검토 시작값.
var DefaultLimits = Limits{MaxComponents: 100000, MaxLocationsPerItem: 1024, MaxDepth: 32}

// 변환을 거부하는 이유. 진단(Diagnostic)과 달리 결과가 없다.
var (
	ErrMalformed       = errors.New("malformed JSON")
	ErrNotCycloneDX    = errors.New("not a CycloneDX document")
	ErrUnsupportedSpec = errors.New("unsupported specVersion")
	ErrLimitExceeded   = errors.New("limit exceeded")
	ErrTrailingContent = errors.New("trailing content after the JSON document")
)

// standardRuleSpec — 표준 규칙이 무엇을 읽는지 적은 고정 문자열. 규칙의 내용 해시가 이것의 해시다.
var standardRuleSpec = []byte(`{"id":"standard-occurrences","revision":"1","reads":"components[].evidence.occurrences[]","lineBase":"unknown"}`)

// StandardRule — 표준 규칙의 식별. 내용 해시는 규칙이 무엇을 읽는지 적은 고정 문자열의 해시다 —
// 동작을 바꾸면 그 문자열과 판을 함께 바꾼다.
func StandardRule() RuleRef {
	return RuleRef{Source: "standard", ID: StandardRuleID, Revision: StandardRuleRevision, SHA256: sha256Hex(standardRuleSpec)}
}

// primitive 열거값(CycloneDX 명세 master 6470e34e의 bom-1.6·1.7 스키마). 1.7에 key-wrap이 더해졌다.
var primitives = map[string]map[string]bool{
	"1.6": set("drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"),
	"1.7": set("drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "key-wrap", "other", "unknown"),
}

// Convert — 표준 규칙으로 읽는다. A1은 표준 규칙만 있다(프리셋·사용자 매핑은 A2).
func Convert(raw []byte, lim Limits) (*Interpretation, error) {
	doc, err := decode(raw)
	if err != nil {
		return nil, err
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, ErrNotCycloneDX
	}
	if s, _ := obj["bomFormat"].(string); s != "CycloneDX" {
		return nil, ErrNotCycloneDX
	}
	spec, _ := obj["specVersion"].(string)
	if primitives[spec] == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedSpec, spec)
	}

	rule := StandardRule()
	in := &Interpretation{
		SchemaVersion:    SchemaVersion,
		ConverterVersion: ConverterVersion,
		InputSHA256:      sha256Hex(raw),
		SpecVersion:      spec,
		Rules:            []RuleRef{rule},
		ExcludedRuleIDs:  []string{},
		Producer:         producer(obj),
		Items:            []Item{},
		Diagnostics:      []Diagnostic{},
		Counts:           Counts{Diagnostics: map[string]int{}},
	}
	in.ID = interpretationID(in)

	c := &converter{in: in, spec: spec, rule: rule, lim: lim}
	if err := c.components(obj["components"], "/components", 0); err != nil {
		return nil, err
	}
	for _, it := range in.Items {
		if len(it.Locations) > 0 {
			in.Counts.ItemsWithLocation++
		}
		in.Counts.Locations += len(it.Locations)
		for _, d := range it.Diagnostics {
			in.Counts.Diagnostics[d.Code]++
		}
		for _, l := range it.Locations {
			for _, d := range l.Diagnostics {
				in.Counts.Diagnostics[d.Code]++
			}
		}
	}
	for _, d := range in.Diagnostics {
		in.Counts.Diagnostics[d.Code]++
	}
	return in, nil
}

type converter struct {
	in    *Interpretation
	spec  string
	rule  RuleRef
	lim   Limits
	total int
}

func (c *converter) components(v any, ptr string, depth int) error {
	arr, ok := v.([]any)
	if !ok {
		return nil // components가 없거나 배열이 아니다 — 대상이 없다
	}
	if depth > c.lim.MaxDepth {
		return fmt.Errorf("%w: components nested deeper than %d at %s", ErrLimitExceeded, c.lim.MaxDepth, ptr)
	}
	for i, e := range arr {
		p := ptr + "/" + strconv.Itoa(i)
		c.total++
		if c.total > c.lim.MaxComponents {
			return fmt.Errorf("%w: more than %d components", ErrLimitExceeded, c.lim.MaxComponents)
		}
		comp, ok := e.(map[string]any)
		if !ok {
			c.in.Diagnostics = append(c.in.Diagnostics, Diagnostic{Code: DiagNotAnObject, Pointer: p})
			continue
		}
		if t, _ := comp["type"].(string); t == "cryptographic-asset" {
			c.in.Counts.Components++
			it, err := c.item(comp, p)
			if err != nil {
				return err
			}
			c.in.Items = append(c.in.Items, it)
		} else {
			c.in.Counts.OutOfScope++
		}
		if err := c.components(comp["components"], p+"/components", depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (c *converter) item(comp map[string]any, ptr string) (Item, error) {
	it := Item{ComponentPointer: ptr, Reported: []Field{}, External: []Field{}, Locations: []Location{}, Diagnostics: []Diagnostic{}}
	it.ID = digest(c.in.ID, ptr)

	for _, k := range []string{"name", "bom-ref", "version"} {
		addScalar(&it.Reported, k, comp[k], ptr+"/"+escape(k))
	}
	if cp, ok := comp["cryptoProperties"].(map[string]any); ok {
		c.cryptoProperties(&it, cp, ptr+"/cryptoProperties")
	}
	if props, ok := comp["properties"].([]any); ok {
		for i, e := range props {
			pp := ptr + "/properties/" + strconv.Itoa(i)
			if m, ok := e.(map[string]any); ok {
				name, _ := m["name"].(string)
				val, _ := scalarString(m["value"])
				it.External = append(it.External, Field{Name: name, Value: val, Pointer: pp})
			}
		}
	}
	if ev, ok := comp["evidence"].(map[string]any); ok {
		if occ, ok := ev["occurrences"].([]any); ok {
			if len(occ) > c.lim.MaxLocationsPerItem {
				return it, fmt.Errorf("%w: %d occurrences at %s (limit %d)", ErrLimitExceeded, len(occ), ptr, c.lim.MaxLocationsPerItem)
			}
			for i, e := range occ {
				op := ptr + "/evidence/occurrences/" + strconv.Itoa(i)
				m, ok := e.(map[string]any)
				if !ok {
					it.Diagnostics = append(it.Diagnostics, Diagnostic{Code: DiagNotAnObject, Pointer: op})
					continue
				}
				if l, ok := c.occurrence(it.ID, m, op, &it); ok {
					it.Locations = append(it.Locations, l)
				}
			}
		}
	}
	return it, nil
}

func (c *converter) cryptoProperties(it *Item, cp map[string]any, ptr string) {
	addScalar(&it.Reported, "assetType", cp["assetType"], ptr+"/assetType")
	addScalar(&it.Reported, "oid", cp["oid"], ptr+"/oid")
	if ap, ok := cp["algorithmProperties"].(map[string]any); ok {
		app := ptr + "/algorithmProperties"
		if p, ok := ap["primitive"].(string); ok && !primitives[c.spec][p] {
			it.Diagnostics = append(it.Diagnostics, Diagnostic{Code: DiagPrimitiveNotInVer, Pointer: app + "/primitive",
				Detail: fmt.Sprintf("%q is not a primitive in CycloneDX %s; kept as reported", p, c.spec)})
		}
		if _, ok := ap["curve"]; ok && c.spec == "1.7" {
			it.Diagnostics = append(it.Diagnostics, Diagnostic{Code: DiagDeprecatedField, Pointer: app + "/curve",
				Detail: "deprecated in CycloneDX 1.7 (use ellipticCurve); kept as reported"})
		}
		for _, k := range []string{"primitive", "algorithmFamily", "parameterSetIdentifier", "mode", "padding", "curve", "ellipticCurve",
			"executionEnvironment", "implementationPlatform", "classicalSecurityLevel", "nistQuantumSecurityLevel"} {
			addScalar(&it.Reported, "algorithmProperties."+k, ap[k], app+"/"+escape(k))
		}
		addArray(&it.Reported, "algorithmProperties.cryptoFunctions", ap["cryptoFunctions"], app+"/cryptoFunctions")
		addArray(&it.Reported, "algorithmProperties.certificationLevel", ap["certificationLevel"], app+"/certificationLevel")
	}
	if rm, ok := cp["relatedCryptoMaterialProperties"].(map[string]any); ok {
		rp := ptr + "/relatedCryptoMaterialProperties"
		for _, k := range []string{"type", "size", "format", "state"} {
			addScalar(&it.Reported, "relatedCryptoMaterialProperties."+k, rm[k], rp+"/"+k)
		}
	}
	if pp, ok := cp["protocolProperties"].(map[string]any); ok {
		addScalar(&it.Reported, "protocolProperties.type", pp["type"], ptr+"/protocolProperties/type")
		addScalar(&it.Reported, "protocolProperties.version", pp["version"], ptr+"/protocolProperties/version")
	}
}

// occurrence — 표준 위치 하나. location 문자열이 없으면 위치를 만들지 않고 알린다.
func (c *converter) occurrence(itemID string, m map[string]any, ptr string, it *Item) (Location, bool) {
	path, ok := m["location"].(string)
	if !ok || path == "" {
		it.Diagnostics = append(it.Diagnostics, Diagnostic{Code: DiagLocationMissing, Pointer: ptr})
		return Location{}, false
	}
	l := Location{
		Rule:           c.rule,
		SourcePointers: map[string]string{"occurrence": ptr},
		Reported:       ReportedLocation{Path: path},
		LineBase:       BaseUnknown,
		Normalized:     Normalized{Path: path},
		Kind:           LocationKindNotSupplied,
		Diagnostics:    []Diagnostic{},
	}
	if v, present := m["line"]; present {
		if n, ok := nonNegInt(v); ok {
			l.Reported.Line = &n
		} else {
			l.Diagnostics = append(l.Diagnostics, Diagnostic{Code: DiagInvalidLine, Pointer: ptr + "/line"})
		}
	}
	if v, present := m["offset"]; present {
		if n, ok := nonNegInt(v); ok {
			l.Reported.Offset = &n
		} else {
			l.Diagnostics = append(l.Diagnostics, Diagnostic{Code: DiagInvalidOffset, Pointer: ptr + "/offset"})
		}
	}
	l.Reported.Symbol, _ = m["symbol"].(string)
	l.Reported.Context, _ = m["additionalContext"].(string)
	// 표준은 줄의 시작 기준을 정하지 않는다(정수 ≥0만). 그래서 줄을 정규화하지 않는다(계약 D1).
	if l.Reported.Line != nil {
		l.Normalized.AbsentReason = "line base unknown"
		l.Diagnostics = append(l.Diagnostics, Diagnostic{Code: DiagLineBaseUnknown, Pointer: ptr + "/line"})
	}
	l.ID = locationID(itemID, l.Rule, l.SourcePointers)
	return l, true
}

// producer — metadata.tools. 1.5 이후 권하는 객체 꼴({components, services})과 옛 배열 꼴을 모두 읽는다.
func producer(obj map[string]any) []Field {
	out := []Field{}
	md, _ := obj["metadata"].(map[string]any)
	if md == nil {
		return out
	}
	add := func(arr []any, ptr string) {
		for i, e := range arr {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			p := ptr + "/" + strconv.Itoa(i)
			for _, k := range []string{"vendor", "name", "version"} {
				addScalar(&out, k, m[k], p+"/"+k)
			}
			if g, ok := m["group"]; ok {
				addScalar(&out, "group", g, p+"/group")
			}
		}
	}
	switch t := md["tools"].(type) {
	case []any:
		add(t, "/metadata/tools")
	case map[string]any:
		if a, ok := t["components"].([]any); ok {
			add(a, "/metadata/tools/components")
		}
		if a, ok := t["services"].([]any); ok {
			add(a, "/metadata/tools/services")
		}
	}
	return out
}

// decode — 숫자를 json.Number로 읽고, 문서 뒤에 다른 내용이 붙으면 거부한다.
func decode(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, err := d.Token(); err == nil {
		return nil, ErrTrailingContent
	}
	return v, nil
}

func addScalar(dst *[]Field, name string, v any, ptr string) {
	if s, ok := scalarString(v); ok {
		*dst = append(*dst, Field{Name: name, Value: s, Pointer: ptr})
	}
}

func addArray(dst *[]Field, name string, v any, ptr string) {
	arr, ok := v.([]any)
	if !ok {
		return
	}
	for i, e := range arr {
		addScalar(dst, name, e, ptr+"/"+strconv.Itoa(i))
	}
}

// scalarString — 문자열·숫자·불을 원래 표기대로. 객체·배열·null은 값이 아니다.
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case bool:
		return strconv.FormatBool(t), true
	}
	return "", false
}

func nonNegInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	// 1.0·1e2 같은 표기는 정수로 받지 않는다(스키마가 integer를 요구한다). Int64가 그것들을 거부한다.
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return i, i >= 0
}

// escape — JSON Pointer 토큰(RFC 6901).
func escape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// digest — 여러 값의 해시. 구분자로 이어 붙이지 않고 JSON 배열로 직렬화해 경계가 모호하지 않게 한다
// (구분 문자가 값 안에 들어가 다른 입력이 같은 바이트가 되는 일을 막는다).
func digest(parts ...any) string {
	b, err := json.Marshal(parts)
	if err != nil {
		panic(err) // 문자열·구조체만 넘긴다
	}
	return sha256Hex(b)
}

func interpretationID(in *Interpretation) string {
	return digest("interpretation", in.SchemaVersion, in.ConverterVersion, in.InputSHA256, in.Rules, in.ExcludedRuleIDs)
}

// locationID — 근거 항목 + 규칙 식별 + 원본 포인터. 두 규칙이 같은 포인터를 읽어도 위치는 따로다(계약 D7).
// map은 encoding/json이 키 순서로 직렬화하므로 결정론적이다.
func locationID(itemID string, r RuleRef, ptrs map[string]string) string {
	return digest("location", itemID, r, ptrs)
}
