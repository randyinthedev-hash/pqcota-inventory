// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sourceevidence

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// LoadedMap — 변환에 쓸 설정 하나. 원문을 함께 둔다(저장소가 원문을 보관하고, 결과는 원문 해시를 가리킨다).
type LoadedMap struct {
	Source string // "preset" 또는 "user"
	Raw    []byte
	Map    *Map
}

// LoadMap — 사용자 설정 원문을 읽는다.
func LoadMap(raw []byte) (*LoadedMap, error) {
	m, err := ParseMap(raw)
	if err != nil {
		return nil, err
	}
	return &LoadedMap{Source: "user", Raw: raw, Map: m}, nil
}

// MapRef — 변환에 쓴 설정. 결과 ID에 들어간다 — 같은 규칙이라도 원문이 다르면 다른 결과다(설계 §6이 허용한다).
type MapRef struct {
	Source   string `json:"source"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"` // 원문 바이트의 해시
}

// RuleMatch — 규칙마다 몇 컴포넌트에 맞았고 위치를 몇 개 만들었나. 한 번도 맞지 않은 규칙은 설정 실수일 수 있다(설계 §5.4).
type RuleMatch struct {
	Rule       RuleRef `json:"rule"`
	Components int     `json:"components"`
	Locations  int     `json:"locations"`
}

// 매핑 진단 코드. map-로 시작하는 것은 명시한 매핑의 오류다 — 저장을 거부한다(Refusals).
const (
	DiagMapAmbiguous     = "map-ambiguous"      // 하나여야 할 값이 여럿(each 없는 combined, 분리 필드의 property)
	DiagMapUnparsable    = "map-unparsable"     // 결합 문자열이 파서의 꼴이 아니다
	DiagMapFieldMissing  = "map-field-missing"  // 규칙이 맞은 컴포넌트에서 지정한 다른 필드가 없다
	DiagMapWrongType     = "map-wrong-type"     // 지정한 값의 자료형이 틀리다
	DiagMapInvalidLine   = "map-invalid-line"   // 줄이 음수·0(1 기준)·범위 밖·숫자 아님
	DiagMapInvalidColumn = "map-invalid-column" // 열이 같은 이유로 틀리다
	DiagMapRuleUnmatched = "map-rule-unmatched" // 규칙이 입력 전체에서 한 번도 맞지 않았다(전체 진단)

	DiagColumnBaseUnknown = "column-base-unknown" // 열의 시작 기준을 몰라 정규화하지 않았다
	DiagColumnUnitUnknown = "column-unit-unknown" // 열의 단위를 모른다 — 다른 규칙의 열과 견주지 않는다
)

// Refusals — 저장을 거부할 진단. 명시한 매핑에 변환 오류가 있으면 성공으로 저장하지 않는다(설계 §5.4, 부분 수용 없음).
// 한 번도 맞지 않은 규칙은 allowUnmatched일 때만 받는다(사용자가 위치 없이 계속하겠다고 밝힌 경우).
func Refusals(in *Interpretation, allowUnmatched bool) []Diagnostic {
	var out []Diagnostic
	take := func(ds []Diagnostic) {
		for _, d := range ds {
			if !strings.HasPrefix(d.Code, "map-") {
				continue
			}
			if d.Code == DiagMapRuleUnmatched && allowUnmatched {
				continue
			}
			out = append(out, d)
		}
	}
	take(in.Diagnostics)
	for _, it := range in.Items {
		take(it.Diagnostics)
		for _, l := range it.Locations {
			take(l.Diagnostics)
		}
	}
	return out
}

// appliedRule — 변환 중의 규칙. ref는 결과에 남는 식별이다.
type appliedRule struct {
	ref  RuleRef
	spec LocationSpec
}

// property — 컴포넌트 properties의 한 항목.
type property struct {
	ptr   string
	value any
}

// properties — name이 같은 항목들. 자료형이 틀린 항목은 표준 경로(item)가 이미 진단했으므로 건너뛴다.
func properties(obj map[string]any, base, name string) []property {
	arr, _ := obj["properties"].([]any)
	var out []property
	for i, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := m["name"].(string); n == name {
			out = append(out, property{ptr: base + "/properties/" + strconv.Itoa(i), value: m["value"]})
		}
	}
	return out
}

// applyRule — 컴포넌트 하나에 규칙 하나. 맞았는지(주 필드가 있었는지)를 돌려준다.
func (c *converter) applyRule(r appliedRule, comp map[string]any, ptr string, it *Item) bool {
	d := func(code, p, format string, a ...any) {
		it.Diagnostics = append(it.Diagnostics, Diagnostic{Code: code, Pointer: p, Detail: r.ref.ID + ": " + fmt.Sprintf(format, a...)})
	}
	s := r.spec
	if s.Combined != nil {
		ps := properties(comp, ptr, s.Combined.Property)
		if len(ps) == 0 {
			return false
		}
		if len(ps) > 1 && !s.Combined.Each {
			d(DiagMapAmbiguous, ptr+"/properties", "%d values of %q; set each: true if every value is one location", len(ps), s.Combined.Property)
			return true
		}
		for _, p := range ps {
			str, ok := p.value.(string)
			if !ok {
				d(DiagMapWrongType, p.ptr+"/value", "expected a string, got %s", jsonType(p.value))
				continue
			}
			path, line, col, why := parseCombined(str, s.Combined.Parser)
			if why != "" {
				d(DiagMapUnparsable, p.ptr+"/value", "%q does not fit %s: %s", str, s.Combined.Parser, why)
				continue
			}
			l := c.mapLocation(r, it, map[string]string{"combined": p.ptr}, path, &line, col)
			l.Reported.Raw = str
			it.Locations = append(it.Locations, l)
		}
		return true
	}

	if s.Array != "" {
		x, ok := resolvePointer(comp, s.Array)
		if !ok {
			return false
		}
		arr, ok := x.([]any)
		if !ok {
			d(DiagMapWrongType, ptr+s.Array, "expected an array, got %s", jsonType(x))
			return true
		}
		for i, e := range arr {
			ep := ptr + s.Array + "/" + strconv.Itoa(i)
			el, ok := e.(map[string]any)
			if !ok {
				d(DiagMapWrongType, ep, "expected an object, got %s", jsonType(e))
				continue
			}
			c.splitLocation(r, el, ep, it, true, d)
		}
		return true
	}
	return c.splitLocation(r, comp, ptr, it, false, d)
}

// pick — 선택자로 값 하나. found=false면 없다. 같은 property가 여럿이면 모호함이다.
func pick(sel *Selector, obj map[string]any, base string) (v any, p string, found, ambiguous bool) {
	if sel.ByPointer {
		x, ok := resolvePointer(obj, sel.Pointer)
		return x, base + sel.Pointer, ok, false
	}
	ps := properties(obj, base, sel.Property)
	switch len(ps) {
	case 0:
		return nil, "", false, false
	case 1:
		return ps[0].value, ps[0].ptr + "/value", true, false
	}
	return nil, base + "/properties", true, true
}

// splitLocation — 파일·줄·열을 따로 읽는다. inArray면 배열 요소 하나(맞은 것으로 이미 셌다).
func (c *converter) splitLocation(r appliedRule, obj map[string]any, base string, it *Item, inArray bool,
	d func(code, p, format string, a ...any)) bool {
	s := r.spec
	fv, fp, found, amb := pick(s.File, obj, base)
	if !found {
		if inArray {
			d(DiagMapFieldMissing, base, "file is missing in this element")
		}
		return inArray
	}
	if amb {
		d(DiagMapAmbiguous, fp, "more than one %q for the file", s.File.Property)
		return true
	}
	path, ok := fv.(string)
	if !ok || path == "" {
		if ok {
			d(DiagMapFieldMissing, fp, "file is an empty string")
		} else {
			d(DiagMapWrongType, fp, "file: expected a string, got %s", jsonType(fv))
		}
		return true
	}
	ptrs := map[string]string{"file": fp}

	var line *int64
	if s.Line != nil {
		v, p, found, amb := pick(s.Line, obj, base)
		switch {
		case !found:
			d(DiagMapFieldMissing, base, "line is missing")
			return true
		case amb:
			d(DiagMapAmbiguous, p, "more than one %q for the line", s.Line.Property)
			return true
		}
		n, why := intValue(v)
		if why != "" {
			d(DiagMapInvalidLine, p, "%s", why)
			return true
		}
		line, ptrs["line"] = &n, p
	}
	var col *int64
	if s.Column != nil {
		v, p, found, amb := pick(s.Column, obj, base)
		switch {
		case !found:
			d(DiagMapFieldMissing, base, "column is missing")
			return true
		case amb:
			d(DiagMapAmbiguous, p, "more than one %q for the column", s.Column.Property)
			return true
		}
		n, why := intValue(v)
		if why != "" {
			d(DiagMapInvalidColumn, p, "%s", why)
			return true
		}
		col, ptrs["column"] = &n, p
	}
	it.Locations = append(it.Locations, c.mapLocation(r, it, ptrs, path, line, col))
	return true
}

// intValue — 줄·열 값. properties의 값은 문자열이므로 십진 숫자 문자열도 받는다. JSON 숫자는 표준 경로와 같은 규칙.
func intValue(v any) (int64, string) {
	if s, ok := v.(string); ok {
		if s == "" || !allDigits(s) {
			return 0, fmt.Sprintf("%q is not a non-negative integer", s)
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, "out of range"
		}
		return n, ""
	}
	if _, ok := v.(json.Number); ok {
		return nonNegInt(v)
	}
	return 0, "expected an integer, got " + jsonType(v)
}

// parseCombined — 오른쪽부터 숫자를 뗀다. 경로가 비면 안 된다.
func parseCombined(s, parser string) (path string, line int64, col *int64, why string) {
	cut := func(s string) (string, int64, string) {
		i := strings.LastIndexByte(s, ':')
		if i < 0 {
			return "", 0, "no colon"
		}
		num := s[i+1:]
		if num == "" || !allDigits(num) {
			return "", 0, fmt.Sprintf("%q is not a number", num)
		}
		n, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			return "", 0, "number out of range"
		}
		return s[:i], n, ""
	}
	rest := s
	if parser == ParserPathLineColumn {
		r, n, w := cut(rest)
		if w != "" {
			return "", 0, nil, "column: " + w
		}
		rest, col = r, &n
	}
	p, n, w := cut(rest)
	if w != "" {
		return "", 0, nil, "line: " + w
	}
	if p == "" {
		return "", 0, nil, "empty path"
	}
	return p, n, col, ""
}

// mapLocation — 보고값과 규칙의 기준으로 위치를 만든다. 기준을 모르는 값은 정규화하지 않는다.
func (c *converter) mapLocation(r appliedRule, it *Item, ptrs map[string]string, path string, line, col *int64) Location {
	s := r.spec
	l := Location{
		Rule:           r.ref,
		SourcePointers: ptrs,
		Reported:       ReportedLocation{Path: path, Line: line, Column: col},
		LineBase:       s.LineBase,
		Normalized:     Normalized{Path: path},
		Kind:           LocationKindNotSupplied,
		Diagnostics:    []Diagnostic{},
	}
	var absent []string
	ld := func(code, key, detail string) {
		l.Diagnostics = append(l.Diagnostics, Diagnostic{Code: code, Pointer: ptrs[key], Detail: r.ref.ID + ": " + detail})
	}
	lineKey := "line"
	if _, ok := ptrs["combined"]; ok {
		lineKey = "combined"
	}
	if line != nil {
		switch n, why := normalize(*line, s.LineBase); {
		case why == "unknown":
			absent = append(absent, "line base unknown")
			ld(DiagLineBaseUnknown, lineKey, "line kept as reported")
		case why != "":
			absent = append(absent, "line invalid")
			ld(DiagMapInvalidLine, lineKey, why)
		default:
			l.Normalized.Line = &n
		}
	}
	if col != nil {
		l.ColumnBase, l.ColumnUnit = s.ColumnBase, s.ColumnUnit
		colKey := "column"
		if lineKey == "combined" {
			colKey = "combined"
		}
		switch n, why := normalize(*col, s.ColumnBase); {
		case why == "unknown":
			absent = append(absent, "column base unknown")
			ld(DiagColumnBaseUnknown, colKey, "column kept as reported")
		case why != "":
			absent = append(absent, "column invalid")
			ld(DiagMapInvalidColumn, colKey, why)
		default:
			l.Normalized.Column = &n
		}
		if s.ColumnUnit == "unknown" {
			ld(DiagColumnUnitUnknown, colKey, "column unit unknown")
		}
	}
	l.Normalized.AbsentReason = strings.Join(absent, "; ")
	l.ID = locationID(it.ID, l.Rule, l.SourcePointers)
	return l
}

// normalize — 1부터 세는 값으로. why가 "unknown"이면 기준을 모른다.
func normalize(v int64, b Base) (int64, string) {
	switch b {
	case Base1:
		if v == 0 {
			return 0, "0 is not a valid value when counting from 1"
		}
		return v, ""
	case Base0:
		if v == 1<<63-1 {
			return 0, "out of range"
		}
		return v + 1, ""
	}
	return 0, "unknown"
}
