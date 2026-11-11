// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sourceevidence

// 매핑 설정(A2) — 표준 occurrence가 아닌 자리(properties, 컴포넌트 안의 다른 필드)에 있는 소스 위치를 읽는 규칙.
// 형식은 계약 검토 §4의 `pqcota-source-map/v1`이다. 선언형이고 실행식이 없다(설계 §5.1).
//
// 검증은 스키마(§4)와 스키마 밖 규칙(§4 아래 목록)을 함께 본다. 알 수 없는 키는 거부한다. 고칠 곳을 한 번에 알 수 있게
// 문제를 모두 모아 한 오류로 낸다.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MapFormat — 이 변환기가 읽는 매핑 설정의 판. 다른 판은 거부한다(조용히 새 뜻으로 읽지 않는다, 계약 §6.1).
const MapFormat = "pqcota-source-map/v1"

// MaxMapBytes — 설정 원문 상한(검토 시작값, 설계 §6). 읽는 쪽(CLI)이 읽기 전에도 건다.
const MaxMapBytes = 256 << 10

const maxMapRules = 32

// ErrBadMap — 설정 자체가 잘못됐다. 변환하지 않는다(설계 §5.4).
var ErrBadMap = errors.New("source map is not valid")

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var revisionPattern = regexp.MustCompile(`^[0-9]{1,6}$`)

// Map — 검증을 통과한 매핑 설정.
type Map struct {
	ID       string
	Revision string
	Rules    []MapRule
}

// MapRule — 규칙 하나.
type MapRule struct {
	ID  string
	Loc LocationSpec
}

// LocationSpec — 위치를 어디서 어떻게 읽나. Combined와 File은 둘 중 하나만 있다.
type LocationSpec struct {
	Combined   *CombinedSpec `json:"combined,omitempty"`
	File       *Selector     `json:"file,omitempty"`
	Line       *Selector     `json:"line,omitempty"`
	Column     *Selector     `json:"column,omitempty"`
	Array      string        `json:"array,omitempty"` // 컴포넌트 기준 배열 포인터. 비면 없음
	LineBase   Base          `json:"lineBase"`
	ColumnBase Base          `json:"columnBase,omitempty"`
	ColumnUnit string        `json:"columnUnit,omitempty"`
}

// CombinedSpec — 한 값에 위치 전체가 든 property.
type CombinedSpec struct {
	Property string `json:"property"`
	Each     bool   `json:"each"`
	Parser   string `json:"parser"`
}

// Selector — property 이름 또는 JSON Pointer 하나.
type Selector struct {
	Property string `json:"property,omitempty"`
	Pointer  string `json:"pointer,omitempty"`
	// ByPointer — Pointer가 쓰였는가(빈 포인터 ""도 문서 전체를 가리키는 올바른 포인터다).
	ByPointer bool `json:"byPointer,omitempty"`
}

// 내장 파서. 오른쪽부터 숫자를 떼어 경로 안의 콜론(Windows 드라이브)과 구분한다(계약 D5).
const (
	ParserPathLine       = "path:line"
	ParserPathLineColumn = "path:line:column"
)

var columnUnits = set("byte", "utf16", "codepoint", "unknown")

// ParseMap — 원문을 검증해 읽는다. 문제가 있으면 모두 모아 ErrBadMap으로 낸다.
func ParseMap(raw []byte) (*Map, error) {
	if len(raw) > MaxMapBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrBadMap, MaxMapBytes)
	}
	doc, err := decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMap, err)
	}
	v := &mapValidator{}
	m := v.root(doc)
	if len(v.problems) > 0 {
		return nil, fmt.Errorf("%w:\n  %s", ErrBadMap, strings.Join(v.problems, "\n  "))
	}
	return m, nil
}

type mapValidator struct{ problems []string }

func (v *mapValidator) bad(ptr, format string, a ...any) {
	if ptr == "" {
		ptr = "(root)"
	}
	v.problems = append(v.problems, ptr+": "+fmt.Sprintf(format, a...))
}

// keys — 허용한 키만 있는지, 필수 키가 다 있는지.
func (v *mapValidator) keys(obj map[string]any, ptr string, allowed []string, required []string) {
	ok := set(allowed...)
	var unknown []string
	for k := range obj {
		if !ok[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		v.bad(ptr, "unknown key %q", k)
	}
	for _, k := range required {
		if _, has := obj[k]; !has {
			v.bad(ptr, "missing %q", k)
		}
	}
}

func (v *mapValidator) object(x any, ptr string) (map[string]any, bool) {
	m, ok := x.(map[string]any)
	if !ok {
		v.bad(ptr, "expected an object, got %s", jsonType(x))
	}
	return m, ok
}

func (v *mapValidator) str(obj map[string]any, k, ptr string) (string, bool) {
	x, has := obj[k]
	if !has {
		return "", false
	}
	s, ok := x.(string)
	if !ok {
		v.bad(ptr+"/"+k, "expected a string, got %s", jsonType(x))
	}
	return s, ok
}

func (v *mapValidator) root(doc any) *Map {
	obj, ok := v.object(doc, "")
	if !ok {
		return nil
	}
	v.keys(obj, "", []string{"format", "id", "revision", "rules"}, []string{"format", "id", "revision", "rules"})
	if f, ok := v.str(obj, "format", ""); ok && f != MapFormat {
		v.bad("/format", "%q is not supported; this converter reads %q", f, MapFormat)
	}
	m := &Map{}
	if id, ok := v.str(obj, "id", ""); ok {
		if !idPattern.MatchString(id) {
			v.bad("/id", "%q must match %s", id, idPattern)
		}
		m.ID = id
	}
	if r, ok := v.str(obj, "revision", ""); ok {
		if !revisionPattern.MatchString(r) {
			v.bad("/revision", "%q must be 1 to 6 digits", r)
		}
		m.Revision = r
	}
	rules, has := obj["rules"]
	if !has {
		return m
	}
	arr, ok := rules.([]any)
	if !ok {
		v.bad("/rules", "expected an array, got %s", jsonType(rules))
		return m
	}
	if len(arr) == 0 || len(arr) > maxMapRules {
		v.bad("/rules", "needs 1 to %d rules, has %d", maxMapRules, len(arr))
	}
	seen := map[string]bool{}
	for i, x := range arr {
		p := fmt.Sprintf("/rules/%d", i)
		r, ok := v.rule(x, p)
		if !ok {
			continue
		}
		if seen[r.ID] {
			v.bad(p+"/id", "rule id %q is used twice", r.ID)
		}
		seen[r.ID] = true
		m.Rules = append(m.Rules, r)
	}
	return m
}

func (v *mapValidator) rule(x any, ptr string) (MapRule, bool) {
	obj, ok := v.object(x, ptr)
	if !ok {
		return MapRule{}, false
	}
	v.keys(obj, ptr, []string{"id", "componentTypes", "locations"}, []string{"id", "componentTypes", "locations"})
	var r MapRule
	if id, ok := v.str(obj, "id", ptr); ok {
		switch {
		case !idPattern.MatchString(id):
			v.bad(ptr+"/id", "%q must match %s", id, idPattern)
		case strings.HasPrefix(id, "standard-"):
			v.bad(ptr+"/id", "%q: the standard- prefix is kept for standard rules", id)
		}
		r.ID = id
	}
	if ct, has := obj["componentTypes"]; has {
		arr, ok := ct.([]any)
		if !ok || len(arr) != 1 || arr[0] != "cryptographic-asset" {
			v.bad(ptr+"/componentTypes", `must be ["cryptographic-asset"] in this version`)
		}
	}
	if l, has := obj["locations"]; has {
		r.Loc = v.locations(l, ptr+"/locations")
	}
	return r, true
}

func (v *mapValidator) locations(x any, ptr string) LocationSpec {
	var s LocationSpec
	obj, ok := v.object(x, ptr)
	if !ok {
		return s
	}
	v.keys(obj, ptr, []string{"from", "combined", "file", "line", "column", "array", "lineBase", "columnBase", "columnUnit"},
		[]string{"from", "lineBase"})
	if f, has := obj["from"]; has && f != "component" {
		v.bad(ptr+"/from", `must be "component"`)
	}
	_, hasCombined := obj["combined"]
	_, hasFile := obj["file"]
	_, hasLine := obj["line"]
	_, hasColumn := obj["column"]
	_, hasArray := obj["array"]
	_, hasColBase := obj["columnBase"]
	_, hasColUnit := obj["columnUnit"]

	if b, has := obj["lineBase"]; has {
		s.LineBase = v.base(b, ptr+"/lineBase")
	}
	if hasColBase {
		s.ColumnBase = v.base(obj["columnBase"], ptr+"/columnBase")
	}
	if hasColUnit {
		u, ok := v.str(obj, "columnUnit", ptr)
		if ok && !columnUnits[u] {
			v.bad(ptr+"/columnUnit", "%q must be one of byte, utf16, codepoint, unknown", u)
		}
		s.ColumnUnit = u
	}

	switch {
	case hasCombined && (hasFile || hasLine || hasColumn || hasArray):
		v.bad(ptr, "combined cannot be used together with file, line, column or array")
	case !hasCombined && !hasFile:
		v.bad(ptr, "needs either combined or file")
	}

	if hasCombined {
		s.Combined = v.combined(obj["combined"], ptr+"/combined")
		if s.Combined != nil {
			switch s.Combined.Parser {
			case ParserPathLine:
				if hasColBase || hasColUnit {
					v.bad(ptr, "parser path:line has no column; remove columnBase and columnUnit")
				}
			case ParserPathLineColumn:
				if !hasColBase || !hasColUnit {
					v.bad(ptr, `parser path:line:column needs columnBase and columnUnit ("unknown" is allowed)`)
				}
			}
		}
		return s
	}
	if hasFile {
		s.File = v.selector(obj["file"], ptr+"/file")
	}
	if hasLine {
		s.Line = v.selector(obj["line"], ptr+"/line")
	}
	if hasColumn {
		s.Column = v.selector(obj["column"], ptr+"/column")
		if !hasLine || !hasColBase || !hasColUnit {
			v.bad(ptr+"/column", "column needs line, columnBase and columnUnit")
		}
	} else if hasColBase || hasColUnit {
		v.bad(ptr, "columnBase and columnUnit are only for a column")
	}
	if hasArray {
		a, ok := v.str(obj, "array", ptr)
		if ok && !validPointer(a, false) {
			v.bad(ptr+"/array", "%q is not a JSON Pointer to a field", a)
		}
		s.Array = a
	}
	return s
}

func (v *mapValidator) combined(x any, ptr string) *CombinedSpec {
	obj, ok := v.object(x, ptr)
	if !ok {
		return nil
	}
	v.keys(obj, ptr, []string{"property", "each", "parser"}, []string{"property", "parser"})
	c := &CombinedSpec{}
	if p, ok := v.str(obj, "property", ptr); ok {
		if len(p) == 0 || len(p) > 256 {
			v.bad(ptr+"/property", "must be 1 to 256 characters")
		}
		c.Property = p
	}
	if e, has := obj["each"]; has {
		b, ok := e.(bool)
		if !ok {
			v.bad(ptr+"/each", "expected true or false, got %s", jsonType(e))
		}
		c.Each = b
	}
	if p, ok := v.str(obj, "parser", ptr); ok {
		if p != ParserPathLine && p != ParserPathLineColumn {
			v.bad(ptr+"/parser", "%q must be %q or %q", p, ParserPathLine, ParserPathLineColumn)
		}
		c.Parser = p
	}
	return c
}

func (v *mapValidator) selector(x any, ptr string) *Selector {
	obj, ok := v.object(x, ptr)
	if !ok {
		return nil
	}
	v.keys(obj, ptr, []string{"property", "pointer"}, nil)
	_, hasP := obj["property"]
	_, hasQ := obj["pointer"]
	if hasP == hasQ {
		v.bad(ptr, "needs exactly one of property or pointer")
	}
	s := &Selector{}
	if p, ok := v.str(obj, "property", ptr); ok {
		if len(p) == 0 || len(p) > 256 {
			v.bad(ptr+"/property", "must be 1 to 256 characters")
		}
		s.Property = p
	}
	if q, ok := v.str(obj, "pointer", ptr); ok {
		if !validPointer(q, true) {
			v.bad(ptr+"/pointer", "%q is not a JSON Pointer", q)
		}
		s.Pointer, s.ByPointer = q, true
	}
	return s
}

func (v *mapValidator) base(x any, ptr string) Base {
	switch t := x.(type) {
	case string:
		if t == "unknown" {
			return BaseUnknown
		}
	case json.Number:
		switch t.String() {
		case "0":
			return Base0
		case "1":
			return Base1
		}
	}
	v.bad(ptr, `must be 0, 1 or "unknown"`)
	return ""
}

// validPointer — RFC 6901. allowEmpty면 ""(대상 전체)도 받는다. ~ 뒤에는 0이나 1만 온다.
func validPointer(p string, allowEmpty bool) bool {
	if p == "" {
		return allowEmpty
	}
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '~' && (i+1 >= len(p) || (p[i+1] != '0' && p[i+1] != '1')) {
			return false
		}
	}
	return true
}

// resolvePointer — root에서 포인터를 따라간다. 없으면 false.
func resolvePointer(root any, p string) (any, bool) {
	if p == "" {
		return root, true
	}
	cur := root
	for _, tok := range strings.Split(p[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch t := cur.(type) {
		case map[string]any:
			x, ok := t[tok]
			if !ok {
				return nil, false
			}
			cur = x
		case []any:
			i, ok := arrayIndex(tok)
			if !ok || i >= len(t) {
				return nil, false
			}
			cur = t[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// arrayIndex — RFC 6901의 배열 첨자: 0이거나 0으로 시작하지 않는 숫자.
func arrayIndex(tok string) (int, bool) {
	if tok == "" || !allDigits(tok) || (len(tok) > 1 && tok[0] == '0') || len(tok) > 9 {
		return 0, false
	}
	n := 0
	for _, c := range tok {
		n = n*10 + int(c-'0')
	}
	return n, true
}

// ruleRef — 규칙의 식별. ID는 「설정 id/규칙 id」, 판은 설정의 revision, 내용 해시는 정규화한 규칙의 해시다.
// JSON 표현(공백·키 순서)이 달라도 같은 규칙이면 내용 해시가 같다. 설정 원문의 해시는 MapRef가 따로 갖는다.
func ruleRef(source string, m *Map, r MapRule) RuleRef {
	canon, err := json.Marshal(struct {
		ID             string       `json:"id"`
		ComponentTypes []string     `json:"componentTypes"`
		Locations      LocationSpec `json:"locations"`
	}{r.ID, []string{"cryptographic-asset"}, r.Loc})
	if err != nil {
		panic(err) // 문자열·불리언만 있다
	}
	return RuleRef{Source: source, ID: m.ID + "/" + r.ID, Revision: m.Revision, SHA256: sha256Hex(canon)}
}
