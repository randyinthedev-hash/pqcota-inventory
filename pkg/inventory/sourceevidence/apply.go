// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sourceevidence

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// LoadedMap — 변환에 쓸 설정 하나. 검증한 원문의 사본만 쥐고, 바깥에서 바꿀 수 없다.
//
// 파싱한 규칙을 따로 들고 있지 않는다. 변환할 때마다 이 원문에서 규칙을 다시 읽으므로, 결과에 적는 원문 해시와
// 실제로 적용한 규칙이 언제나 같은 바이트에서 나온다. 호출자가 넘긴 슬라이스를 나중에 고쳐도 영향이 없다.
type LoadedMap struct {
	source  string // "preset" 또는 "user"
	raw     []byte
	id, rev string
}

func newLoadedMap(source string, raw []byte) (*LoadedMap, error) {
	raw = append([]byte(nil), raw...)
	m, err := ParseMap(raw)
	if err != nil {
		return nil, err
	}
	return &LoadedMap{source: source, raw: raw, id: m.ID, rev: m.Revision}, nil
}

// LoadMap — 사용자 설정 원문을 검증해 읽는다. 원문은 복사한다.
func LoadMap(raw []byte) (*LoadedMap, error) { return newLoadedMap("user", raw) }

// Source — "preset" 또는 "user".
func (lm *LoadedMap) Source() string { return lm.source }

// ID·Revision — 설정의 id와 revision.
func (lm *LoadedMap) ID() string       { return lm.id }
func (lm *LoadedMap) Revision() string { return lm.rev }

// Raw — 원문의 사본.
func (lm *LoadedMap) Raw() []byte { return append([]byte(nil), lm.raw...) }

// SHA256 — 원문의 해시.
func (lm *LoadedMap) SHA256() string { return sha256Hex(lm.raw) }

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

// addLocation·addDiagnostic — 한 항목에 쌓는 위치·진단은 더하는 그 자리에서 잰다. 다 만든 뒤에 세면 큰 반복
// property·배열이 상한을 넘는 위치를 메모리에 모두 만든 뒤에야 거부되고, 잘못된 값만 반복되면 진단이 끝없이 쌓인다.
func (c *converter) addLocation(it *Item, l Location) error {
	if len(it.Locations) >= c.lim.MaxLocationsPerItem {
		return fmt.Errorf("%w: more than %d locations at %s", ErrLimitExceeded, c.lim.MaxLocationsPerItem, it.ComponentPointer)
	}
	it.Locations = append(it.Locations, l)
	return nil
}

func (c *converter) addDiagnostic(it *Item, d Diagnostic) error {
	if len(it.Diagnostics) >= c.lim.MaxDiagnosticsPerItem {
		return fmt.Errorf("%w: more than %d diagnostics at %s", ErrLimitExceeded, c.lim.MaxDiagnosticsPerItem, it.ComponentPointer)
	}
	it.Diagnostics = append(it.Diagnostics, d)
	return nil
}

// eachProperty — name이 같은 항목마다 f. 자료형이 틀린 항목은 표준 경로(item)가 이미 진단했으므로 건너뛴다.
// 목록을 따로 만들지 않는다(반복이 커도 메모리를 쓰지 않는다). f가 오류를 내면 멈춘다.
func eachProperty(obj map[string]any, base, name string, f func(ptr string, value any) error) error {
	arr, _ := obj["properties"].([]any)
	for i, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := m["name"].(string); n == name {
			if err := f(base+"/properties/"+strconv.Itoa(i), m["value"]); err != nil {
				return err
			}
		}
	}
	return nil
}

func countProperties(obj map[string]any, name string) int {
	n := 0
	eachProperty(obj, "", name, func(string, any) error { n++; return nil })
	return n
}

// applyRule — 컴포넌트 하나에 규칙 하나. 맞았는지(주 필드가 있었는지)를 돌려준다. 오류는 상한 초과뿐이다.
func (c *converter) applyRule(r appliedRule, comp map[string]any, ptr string, it *Item) (bool, error) {
	d := func(code, p, format string, a ...any) error {
		return c.addDiagnostic(it, Diagnostic{Code: code, Pointer: p, Detail: r.ref.ID + ": " + fmt.Sprintf(format, a...)})
	}
	s := r.spec
	if s.Combined != nil {
		n := countProperties(comp, s.Combined.Property)
		if n == 0 {
			return false, nil
		}
		if n > 1 && !s.Combined.Each {
			return true, d(DiagMapAmbiguous, ptr+"/properties", "%d values of %q; set each: true if every value is one location", n, s.Combined.Property)
		}
		return true, eachProperty(comp, ptr, s.Combined.Property, func(pp string, value any) error {
			str, ok := value.(string)
			if !ok {
				return d(DiagMapWrongType, pp+"/value", "expected a string, got %s", jsonType(value))
			}
			path, line, col, why := parseCombined(str, s.Combined.Parser)
			if why != "" {
				return d(DiagMapUnparsable, pp+"/value", "%q does not fit %s: %s", str, s.Combined.Parser, why)
			}
			l := c.mapLocation(r, it, map[string]string{"combined": pp}, path, &line, col)
			l.Reported.Raw = str
			return c.addLocation(it, l)
		})
	}

	if s.Array != "" {
		x, ok := resolvePointer(comp, s.Array)
		if !ok {
			return false, nil
		}
		arr, ok := x.([]any)
		if !ok {
			return true, d(DiagMapWrongType, ptr+s.Array, "expected an array, got %s", jsonType(x))
		}
		for i, e := range arr {
			ep := ptr + s.Array + "/" + strconv.Itoa(i)
			el, ok := e.(map[string]any)
			if !ok {
				if err := d(DiagMapWrongType, ep, "expected an object, got %s", jsonType(e)); err != nil {
					return true, err
				}
				continue
			}
			if _, err := c.splitLocation(r, el, ep, it, true, d); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	return c.splitLocation(r, comp, ptr, it, false, d)
}

// pick — 선택자로 값 하나. found=false면 없다. 같은 property가 여럿이면 모호함이다.
func pick(sel *Selector, obj map[string]any, base string) (v any, p string, found, ambiguous bool) {
	if sel.ByPointer {
		x, ok := resolvePointer(obj, sel.Pointer)
		return x, base + sel.Pointer, ok, false
	}
	n := 0
	eachProperty(obj, base, sel.Property, func(pp string, value any) error {
		n++
		if n == 1 {
			v, p = value, pp+"/value"
		}
		return nil
	})
	switch n {
	case 0:
		return nil, "", false, false
	case 1:
		return v, p, true, false
	}
	return nil, base + "/properties", true, true
}

// splitLocation — 파일·줄·열을 따로 읽는다. inArray면 배열 요소 하나(맞은 것으로 이미 셌다).
func (c *converter) splitLocation(r appliedRule, obj map[string]any, base string, it *Item, inArray bool,
	d func(code, p, format string, a ...any) error) (bool, error) {
	s := r.spec
	fv, fp, found, amb := pick(s.File, obj, base)
	if !found {
		if inArray {
			return true, d(DiagMapFieldMissing, base, "file is missing in this element")
		}
		return false, nil
	}
	if amb {
		return true, d(DiagMapAmbiguous, fp, "more than one %q for the file", s.File.Property)
	}
	path, ok := fv.(string)
	if !ok || path == "" {
		if ok {
			return true, d(DiagMapFieldMissing, fp, "file is an empty string")
		}
		return true, d(DiagMapWrongType, fp, "file: expected a string, got %s", jsonType(fv))
	}
	ptrs := map[string]string{"file": fp}

	var line *int64
	if s.Line != nil {
		v, p, found, amb := pick(s.Line, obj, base)
		switch {
		case !found:
			return true, d(DiagMapFieldMissing, base, "line is missing")
		case amb:
			return true, d(DiagMapAmbiguous, p, "more than one %q for the line", s.Line.Property)
		}
		n, why := intValue(v)
		if why != "" {
			return true, d(DiagMapInvalidLine, p, "%s", why)
		}
		line, ptrs["line"] = &n, p
	}
	var col *int64
	if s.Column != nil {
		v, p, found, amb := pick(s.Column, obj, base)
		switch {
		case !found:
			return true, d(DiagMapFieldMissing, base, "column is missing")
		case amb:
			return true, d(DiagMapAmbiguous, p, "more than one %q for the column", s.Column.Property)
		}
		n, why := intValue(v)
		if why != "" {
			return true, d(DiagMapInvalidColumn, p, "%s", why)
		}
		col, ptrs["column"] = &n, p
	}
	return true, c.addLocation(it, c.mapLocation(r, it, ptrs, path, line, col))
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
