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
	"io"
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

// Convert — 표준 규칙만으로 읽는다. ConvertWith(raw, lim, nil)과 같다.
func Convert(raw []byte, lim Limits) (*Interpretation, error) { return ConvertWith(raw, lim, nil) }

// ConvertWith — 표준 규칙과 매핑 설정(프리셋·사용자)으로 읽는다. 규칙은 표준, 설정 순서, 설정 안의 순서로 적용한다.
// 설정마다 id가 달라야 한다(규칙 식별 「설정 id/규칙 id」가 겹치지 않게).
//
// 해석 대상 필드는 「없음」과 「자료형이 틀림」을 구분한다. 없으면 조용히 넘어가고(정상 입력), 있는데
// 자료형이 틀리면 wrong-type으로 알린다 — 틀린 구조를 「항목 없음」처럼 보이게 두지 않는다.
func ConvertWith(raw []byte, lim Limits, maps []*LoadedMap) (*Interpretation, error) {
	seen := map[string]bool{}
	for _, lm := range maps {
		if seen[lm.Map.ID] {
			return nil, fmt.Errorf("%w: two maps with id %q", ErrBadMap, lm.Map.ID)
		}
		seen[lm.Map.ID] = true
	}
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
		Maps:             []MapRef{},
		RuleMatches:      []RuleMatch{},
		Producer:         []Field{},
		Items:            []Item{},
		Diagnostics:      []Diagnostic{},
		Counts:           Counts{Diagnostics: map[string]int{}},
	}
	var applied []appliedRule
	for _, lm := range maps {
		in.Maps = append(in.Maps, MapRef{Source: lm.Source, ID: lm.Map.ID, Revision: lm.Map.Revision, SHA256: sha256Hex(lm.Raw)})
		for _, r := range lm.Map.Rules {
			ref := ruleRef(lm.Source, lm.Map, r)
			in.Rules = append(in.Rules, ref)
			in.RuleMatches = append(in.RuleMatches, RuleMatch{Rule: ref})
			applied = append(applied, appliedRule{ref: ref, spec: r.Loc})
		}
	}
	in.ID = interpretationID(in)

	c := &converter{in: in, spec: spec, rule: rule, lim: lim, rules: applied}
	c.producer(obj)
	if v, present := obj["components"]; present {
		if arr, ok := v.([]any); ok {
			if err := c.components(arr, "/components", 0); err != nil {
				return nil, err
			}
		} else {
			in.Diagnostics = append(in.Diagnostics, wrongType("/components", "array", v))
		}
	}
	for _, m := range in.RuleMatches {
		if m.Components == 0 {
			in.Diagnostics = append(in.Diagnostics, Diagnostic{Code: DiagMapRuleUnmatched,
				Detail: m.Rule.ID + ": matched no component in this input"})
		}
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
	rules []appliedRule // 매핑 규칙. 결과의 RuleMatches와 같은 순서
}

// components — components 배열 하나(자료형은 부른 쪽이 확인했다).
func (c *converter) components(arr []any, ptr string, depth int) error {
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
			c.in.Diagnostics = append(c.in.Diagnostics, wrongType(p, "object", e))
			continue
		}
		// 중첩 components의 자료형은 여기서 먼저 본다. 틀리면 그 컴포넌트의 진단(대상이면 항목, 아니면 전체)에 남긴다.
		sub, hasSub := comp["components"]
		subArr, subOK := sub.([]any)
		var subDiag *Diagnostic
		if hasSub && !subOK {
			d := wrongType(p+"/components", "array", sub)
			subDiag = &d
		}
		if t, _ := comp["type"].(string); t == "cryptographic-asset" {
			c.in.Counts.Components++
			it, err := c.item(comp, p)
			if err != nil {
				return err
			}
			if subDiag != nil {
				it.Diagnostics = append(it.Diagnostics, *subDiag)
			}
			c.in.Items = append(c.in.Items, it)
		} else {
			c.in.Counts.OutOfScope++
			if subDiag != nil {
				c.in.Diagnostics = append(c.in.Diagnostics, *subDiag)
			}
		}
		if hasSub && subOK {
			if err := c.components(subArr, p+"/components", depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *converter) item(comp map[string]any, ptr string) (Item, error) {
	it := Item{ComponentPointer: ptr, Reported: []Field{}, External: []Field{}, Locations: []Location{}, Diagnostics: []Diagnostic{}}
	it.ID = digest(c.in.ID, ptr)
	r := reader{fields: &it.Reported, diags: &it.Diagnostics}

	for _, k := range []string{"name", "bom-ref", "version"} {
		r.scalar(comp, k, k, ptr)
	}
	if cp, ok := r.object(comp, "cryptoProperties", ptr); ok {
		c.cryptoProperties(r, cp, ptr+"/cryptoProperties")
	}
	if props, ok := r.array(comp, "properties", ptr); ok {
		for i, e := range props {
			pp := ptr + "/properties/" + strconv.Itoa(i)
			m, ok := e.(map[string]any)
			if !ok {
				it.Diagnostics = append(it.Diagnostics, wrongType(pp, "object", e))
				continue
			}
			name, _ := m["name"].(string)
			val, _ := scalarString(m["value"])
			it.External = append(it.External, Field{Name: name, Value: val, Pointer: pp})
		}
	}
	if ev, ok := r.object(comp, "evidence", ptr); ok {
		if occ, ok := r.array(ev, "occurrences", ptr+"/evidence"); ok {
			if len(occ) > c.lim.MaxLocationsPerItem {
				return it, fmt.Errorf("%w: %d occurrences at %s (limit %d)", ErrLimitExceeded, len(occ), ptr, c.lim.MaxLocationsPerItem)
			}
			for i, e := range occ {
				op := ptr + "/evidence/occurrences/" + strconv.Itoa(i)
				m, ok := e.(map[string]any)
				if !ok {
					it.Diagnostics = append(it.Diagnostics, wrongType(op, "object", e))
					continue
				}
				if l, ok := c.occurrence(it.ID, m, op, &it); ok {
					it.Locations = append(it.Locations, l)
				}
			}
		}
	}
	for i, r := range c.rules {
		before := len(it.Locations)
		if c.applyRule(r, comp, ptr, &it) {
			c.in.RuleMatches[i].Components++
		}
		c.in.RuleMatches[i].Locations += len(it.Locations) - before
		if len(it.Locations) > c.lim.MaxLocationsPerItem {
			return it, fmt.Errorf("%w: more than %d locations at %s", ErrLimitExceeded, c.lim.MaxLocationsPerItem, ptr)
		}
	}
	return it, nil
}

func (c *converter) cryptoProperties(r reader, cp map[string]any, ptr string) {
	r.scalar(cp, "assetType", "assetType", ptr)
	r.scalar(cp, "oid", "oid", ptr)
	if ap, ok := r.object(cp, "algorithmProperties", ptr); ok {
		app := ptr + "/algorithmProperties"
		if p, ok := ap["primitive"].(string); ok && !primitives[c.spec][p] {
			*r.diags = append(*r.diags, Diagnostic{Code: DiagPrimitiveNotInVer, Pointer: app + "/primitive",
				Detail: fmt.Sprintf("%q is not a primitive in CycloneDX %s; kept as reported", p, c.spec)})
		}
		if _, ok := ap["curve"]; ok && c.spec == "1.7" {
			*r.diags = append(*r.diags, Diagnostic{Code: DiagDeprecatedField, Pointer: app + "/curve",
				Detail: "deprecated in CycloneDX 1.7 (use ellipticCurve); kept as reported"})
		}
		for _, k := range []string{"primitive", "algorithmFamily", "parameterSetIdentifier", "mode", "padding", "curve", "ellipticCurve",
			"executionEnvironment", "implementationPlatform", "classicalSecurityLevel", "nistQuantumSecurityLevel"} {
			r.scalar(ap, k, "algorithmProperties."+k, app)
		}
		r.scalars(ap, "cryptoFunctions", "algorithmProperties.cryptoFunctions", app)
		r.scalars(ap, "certificationLevel", "algorithmProperties.certificationLevel", app)
	}
	if rm, ok := r.object(cp, "relatedCryptoMaterialProperties", ptr); ok {
		for _, k := range []string{"type", "size", "format", "state"} {
			r.scalar(rm, k, "relatedCryptoMaterialProperties."+k, ptr+"/relatedCryptoMaterialProperties")
		}
	}
	if pp, ok := r.object(cp, "protocolProperties", ptr); ok {
		r.scalar(pp, "type", "protocolProperties.type", ptr+"/protocolProperties")
		r.scalar(pp, "version", "protocolProperties.version", ptr+"/protocolProperties")
	}
}

// occurrence — 표준 위치 하나. location이 없으면 위치를 만들지 않고 알린다. 자료형이 틀려도 알린다.
func (c *converter) occurrence(itemID string, m map[string]any, ptr string, it *Item) (Location, bool) {
	v, present := m["location"]
	if !present {
		it.Diagnostics = append(it.Diagnostics, Diagnostic{Code: DiagLocationMissing, Pointer: ptr})
		return Location{}, false
	}
	path, ok := v.(string)
	if !ok {
		it.Diagnostics = append(it.Diagnostics, wrongType(ptr+"/location", "string", v))
		return Location{}, false
	}
	if path == "" {
		it.Diagnostics = append(it.Diagnostics, Diagnostic{Code: DiagLocationMissing, Pointer: ptr + "/location", Detail: "empty string"})
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
		if n, why := nonNegInt(v); why == "" {
			l.Reported.Line = &n
		} else {
			l.Diagnostics = append(l.Diagnostics, Diagnostic{Code: DiagInvalidLine, Pointer: ptr + "/line", Detail: why})
		}
	}
	if v, present := m["offset"]; present {
		if n, why := nonNegInt(v); why == "" {
			l.Reported.Offset = &n
		} else {
			l.Diagnostics = append(l.Diagnostics, Diagnostic{Code: DiagInvalidOffset, Pointer: ptr + "/offset", Detail: why})
		}
	}
	lr := reader{diags: &l.Diagnostics}
	l.Reported.Symbol = lr.str(m, "symbol", ptr)
	l.Reported.Context = lr.str(m, "additionalContext", ptr)
	// 표준은 줄의 시작 기준을 정하지 않는다(정수 ≥0만). 그래서 줄을 정규화하지 않는다(계약 D1).
	if l.Reported.Line != nil {
		l.Normalized.AbsentReason = "line base unknown"
		l.Diagnostics = append(l.Diagnostics, Diagnostic{Code: DiagLineBaseUnknown, Pointer: ptr + "/line"})
	}
	l.ID = locationID(itemID, l.Rule, l.SourcePointers)
	return l, true
}

// producer — metadata.tools가 보고한 도구. 1.5 이후 권하는 객체 꼴({components, services})과 옛 배열 꼴을 모두
// 읽는다. 이름·판뿐 아니라 만든 곳(vendor·supplier·manufacturer·publisher·서비스의 provider)도 남긴다 —
// CBOMkit은 도구를 서비스로 적고 공급자를 provider.name에 둔다.
func (c *converter) producer(obj map[string]any) {
	in := c.in
	r := reader{fields: &in.Producer, diags: &in.Diagnostics}
	md, ok := r.object(obj, "metadata", "")
	if !ok {
		return
	}
	add := func(arr []any, ptr string) {
		for i, e := range arr {
			p := ptr + "/" + strconv.Itoa(i)
			m, ok := e.(map[string]any)
			if !ok {
				in.Diagnostics = append(in.Diagnostics, wrongType(p, "object", e))
				continue
			}
			for _, k := range []string{"vendor", "group", "name", "version", "publisher"} {
				r.scalar(m, k, k, p)
			}
			for _, k := range []string{"supplier", "manufacturer", "provider"} {
				if o, ok := r.object(m, k, p); ok {
					r.scalar(o, "name", k+".name", p+"/"+k)
				}
			}
		}
	}
	tv, present := md["tools"]
	if !present {
		return
	}
	switch t := tv.(type) {
	case []any:
		add(t, "/metadata/tools")
	case map[string]any:
		if a, ok := r.array(t, "components", "/metadata/tools"); ok {
			add(a, "/metadata/tools/components")
		}
		if a, ok := r.array(t, "services", "/metadata/tools"); ok {
			add(a, "/metadata/tools/services")
		}
	default:
		in.Diagnostics = append(in.Diagnostics, wrongType("/metadata/tools", "object or array", tv))
	}
}

// reader — 객체에서 해석 대상 필드를 읽는다. 없으면 넘어가고, 자료형이 틀리면 wrong-type을 남긴다.
type reader struct {
	fields *[]Field
	diags  *[]Diagnostic
}

func (r reader) object(m map[string]any, k, base string) (map[string]any, bool) {
	v, present := m[k]
	if !present {
		return nil, false
	}
	o, ok := v.(map[string]any)
	if !ok {
		*r.diags = append(*r.diags, wrongType(base+"/"+escape(k), "object", v))
	}
	return o, ok
}

func (r reader) array(m map[string]any, k, base string) ([]any, bool) {
	v, present := m[k]
	if !present {
		return nil, false
	}
	a, ok := v.([]any)
	if !ok {
		*r.diags = append(*r.diags, wrongType(base+"/"+escape(k), "array", v))
	}
	return a, ok
}

func (r reader) scalar(m map[string]any, k, name, base string) {
	v, present := m[k]
	if !present {
		return
	}
	p := base + "/" + escape(k)
	if s, ok := scalarString(v); ok {
		*r.fields = append(*r.fields, Field{Name: name, Value: s, Pointer: p})
		return
	}
	*r.diags = append(*r.diags, wrongType(p, "string, number or boolean", v))
}

func (r reader) scalars(m map[string]any, k, name, base string) {
	a, ok := r.array(m, k, base)
	if !ok {
		return
	}
	for i, e := range a {
		p := base + "/" + escape(k) + "/" + strconv.Itoa(i)
		if s, ok := scalarString(e); ok {
			*r.fields = append(*r.fields, Field{Name: name, Value: s, Pointer: p})
		} else {
			*r.diags = append(*r.diags, wrongType(p, "string, number or boolean", e))
		}
	}
}

func (r reader) str(m map[string]any, k, base string) string {
	v, present := m[k]
	if !present {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		*r.diags = append(*r.diags, wrongType(base+"/"+escape(k), "string", v))
	}
	return s
}

func wrongType(ptr, want string, got any) Diagnostic {
	return Diagnostic{Code: DiagWrongType, Pointer: ptr, Detail: "expected " + want + ", got " + jsonType(got)}
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "boolean"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// decode — 숫자를 json.Number로 읽는다. 문서 하나 뒤에는 공백만 올 수 있다 — 다음 읽기가 정확히 io.EOF가
// 아니면(다른 값이든, 잘못된 글자든) 거부한다.
func decode(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrTrailingContent
	}
	return v, nil
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

// nonNegInt — JSON Schema의 integer는 표기가 아니라 값으로 정한다: 17, 17.0, 1.7e1은 모두 정수 17이다.
// 부동소수점으로 바꾸지 않고 십진 표기를 그대로 따져 정수 여부와 int64 범위를 본다. 실패하면 이유를 준다.
func nonNegInt(v any) (int64, string) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, "expected an integer, got " + jsonType(v)
	}
	neg, digits, exp, ok := parseDecimal(n.String())
	if !ok {
		return 0, "not a number"
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return 0, "" // 0, -0, 0.0e5 — 모두 0
	}
	for strings.HasSuffix(digits, "0") { // 끝의 0을 지수로 옮긴다
		digits = digits[:len(digits)-1]
		exp++
	}
	if exp < 0 {
		return 0, "not an integer"
	}
	if neg {
		return 0, "negative"
	}
	if int64(len(digits))+exp > 19 {
		return 0, "out of range"
	}
	i, err := strconv.ParseInt(digits+strings.Repeat("0", int(exp)), 10, 64)
	if err != nil {
		return 0, "out of range"
	}
	return i, ""
}

// parseDecimal — JSON 숫자 표기를 부호·유효 숫자·10의 지수로 나눈다. 값 = digits × 10^exp.
// 지수가 아주 크면 정수 범위를 넘거나(양) 정수가 아니므로(음) 그 판단만 남기도록 큰 값으로 묶는다.
func parseDecimal(s string) (neg bool, digits string, exp int64, ok bool) {
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	}
	mant, e := s, ""
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		mant, e = s[:i], s[i+1:]
	}
	intPart, frac := mant, ""
	if i := strings.IndexByte(mant, '.'); i >= 0 {
		intPart, frac = mant[:i], mant[i+1:]
	}
	if intPart == "" || !allDigits(intPart) || !allDigits(frac) {
		return false, "", 0, false
	}
	digits = intPart + frac
	exp = -int64(len(frac))
	if e != "" {
		sign := int64(1)
		if e[0] == '+' || e[0] == '-' {
			if e[0] == '-' {
				sign = -1
			}
			e = e[1:]
		}
		if e == "" || !allDigits(e) {
			return false, "", 0, false
		}
		if len(strings.TrimLeft(e, "0")) > 9 {
			exp += sign * 1_000_000_000 // 범위 판단에는 이것으로 충분하다
		} else {
			x, _ := strconv.ParseInt(e, 10, 64)
			exp += sign * x
		}
	}
	return neg, digits, exp, true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
	return digest("interpretation", in.SchemaVersion, in.ConverterVersion, in.InputSHA256, in.Rules, in.ExcludedRuleIDs, in.Maps)
}

// IDMatches — ID가 입력 해시·규칙·제외 목록·판에서 다시 계산한 값과 같은가. 저장소가 받기 전에 본다 —
// 이름표와 내용이 어긋난 결과를 저장하면 같은 ID로 다른 해석을 가리키게 된다.
func (in *Interpretation) IDMatches() bool { return in.ID == interpretationID(in) }

// locationID — 근거 항목 + 규칙 식별 + 원본 포인터. 두 규칙이 같은 포인터를 읽어도 위치는 따로다(계약 D7).
// map은 encoding/json이 키 순서로 직렬화하므로 결정론적이다.
func locationID(itemID string, r RuleRef, ptrs map[string]string) string {
	return digest("location", itemID, r, ptrs)
}
