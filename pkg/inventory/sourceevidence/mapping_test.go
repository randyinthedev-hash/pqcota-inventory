// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sourceevidence

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// mapWith — 규칙 하나짜리 설정. locations는 JSON 조각.
func mapWith(locations string) string {
	return `{"format":"pqcota-source-map/v1","id":"t","revision":"1","rules":[{"id":"r","componentTypes":["cryptographic-asset"],"locations":` + locations + `}]}`
}

const (
	locC = `{"from":"component","combined":{"property":"x","each":true,"parser":"path:line:column"},"lineBase":1,"columnBase":1,"columnUnit":"codepoint"}`
	locF = `{"from":"component","file":{"property":"f"},"lineBase":1}`
)

// 계약 검토 §4의 사례(plans/fixtures/check-source-map-schema.py와 같은 것)와 스키마 밖 규칙.
func TestParseMap(t *testing.T) {
	ok := map[string]string{
		"fixture":             locC,
		"line base unknown":   strings.Replace(locC, `"lineBase":1`, `"lineBase":"unknown"`, 1),
		"split file only":     locF,
		"split file+line+col": `{"from":"component","file":{"property":"f"},"line":{"property":"l"},"column":{"property":"c"},"lineBase":1,"columnBase":"unknown","columnUnit":"unknown"}`,
		"array":               `{"from":"component","array":"/evidence/x","file":{"pointer":"/p"},"line":{"pointer":"/l"},"lineBase":0}`,
		"path:line":           `{"from":"component","combined":{"property":"x","parser":"path:line"},"lineBase":1}`,
		"empty pointer":       `{"from":"component","file":{"pointer":""},"lineBase":1}`,
	}
	for name, loc := range ok {
		if _, err := ParseMap([]byte(mapWith(loc))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]string{
		// 스키마(§4)
		"combined+line":           strings.Replace(locC, `"lineBase"`, `"line":{"property":"l"},"lineBase"`, 1),
		"combined+column":         strings.Replace(locC, `"lineBase"`, `"column":{"property":"c"},"lineBase"`, 1),
		"combined+file":           strings.Replace(locC, `"lineBase"`, `"file":{"property":"f"},"lineBase"`, 1),
		"combined+array":          strings.Replace(locC, `"lineBase"`, `"array":"/a","lineBase"`, 1),
		"column without line":     `{"from":"component","file":{"property":"f"},"column":{"property":"c"},"lineBase":1,"columnBase":1,"columnUnit":"byte"}`,
		"column without base":     `{"from":"component","file":{"property":"f"},"line":{"property":"l"},"column":{"property":"c"},"lineBase":1}`,
		"line without file":       `{"from":"component","line":{"property":"l"},"lineBase":1}`,
		"selector both":           `{"from":"component","file":{"property":"f","pointer":"/a"},"lineBase":1}`,
		"selector neither":        `{"from":"component","file":{},"lineBase":1}`,
		"no lineBase":             `{"from":"component","file":{"property":"f"}}`,
		"lineBase 2":              strings.Replace(locF, `"lineBase":1`, `"lineBase":2`, 1),
		"lineBase \"1\"":          strings.Replace(locF, `"lineBase":1`, `"lineBase":"1"`, 1),
		"lineBase 1.0":            strings.Replace(locF, `"lineBase":1`, `"lineBase":1.0`, 1),
		"from other":              strings.Replace(locF, `"component"`, `"document"`, 1),
		"unknown key":             strings.Replace(locF, `"lineBase"`, `"regex":".*","lineBase"`, 1),
		"bad parser":              strings.Replace(locC, `path:line:column`, `regex`, 1),
		"bad unit":                strings.Replace(locC, `codepoint`, `char`, 1),
		"array not a pointer":     `{"from":"component","array":"evidence","file":{"pointer":"/p"},"lineBase":0}`,
		"pointer with bad escape": `{"from":"component","file":{"pointer":"/a~2"},"lineBase":1}`,
		"empty property":          `{"from":"component","file":{"property":""},"lineBase":1}`,
		// 스키마 밖(§4 아래 목록)
		"path:line with column base":       `{"from":"component","combined":{"property":"x","parser":"path:line"},"lineBase":1,"columnBase":1}`,
		"path:line:column without unit":    `{"from":"component","combined":{"property":"x","parser":"path:line:column"},"lineBase":1,"columnBase":1}`,
		"split column base without column": `{"from":"component","file":{"property":"f"},"lineBase":1,"columnBase":1}`,
	}
	for name, loc := range bad {
		if _, err := ParseMap([]byte(mapWith(loc))); !errors.Is(err, ErrBadMap) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	whole := map[string]string{
		"format v2":         strings.Replace(mapWith(locF), "source-map/v1", "source-map/v2", 1),
		"unknown root key":  strings.Replace(mapWith(locF), `"id":"t"`, `"id":"t","x":1`, 1),
		"bad id":            strings.Replace(mapWith(locF), `"id":"t"`, `"id":"T"`, 1),
		"bad revision":      strings.Replace(mapWith(locF), `"revision":"1"`, `"revision":"1.0"`, 1),
		"standard- prefix":  strings.Replace(mapWith(locF), `"id":"r"`, `"id":"standard-x"`, 1),
		"component type":    strings.Replace(mapWith(locF), `["cryptographic-asset"]`, `["data"]`, 1),
		"no rules":          `{"format":"pqcota-source-map/v1","id":"t","revision":"1","rules":[]}`,
		"trailing":          mapWith(locF) + " {}",
		"not json":          `{"format":`,
		"too large":         mapWith(locF) + strings.Repeat(" ", MaxMapBytes),
		"duplicate rule id": `{"format":"pqcota-source-map/v1","id":"t","revision":"1","rules":[{"id":"r","componentTypes":["cryptographic-asset"],"locations":` + locF + `},{"id":"r","componentTypes":["cryptographic-asset"],"locations":` + locF + `}]}`,
		"33 rules":          `{"format":"pqcota-source-map/v1","id":"t","revision":"1","rules":[` + strings.TrimSuffix(strings.Repeat(`{"id":"r","componentTypes":["cryptographic-asset"],"locations":`+locF+`},`, 33), ",") + `]}`,
	}
	for name, raw := range whole {
		if _, err := ParseMap([]byte(raw)); !errors.Is(err, ErrBadMap) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	// 문제는 모두 모아 알린다.
	_, err := ParseMap([]byte(`{"format":"x","id":"T","revision":"a","rules":[],"extra":1}`))
	for _, want := range []string{"/format", "/id", "/revision", "/rules", `unknown key "extra"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

// 설계 §5.2의 예 셋과 내장 프리셋은 받아들여진다.
func TestPresetsAndDesignExamples(t *testing.T) {
	ps := Presets()
	if len(ps) != 2 || ps[0].ID != "cdxgen-dotnet-sourcelocation" || ps[1].ID != "dosai-cyclonedx-location" || ps[0].Revision != "1" {
		t.Fatalf("presets %+v", ps)
	}
	if _, err := LoadPreset("nope"); err == nil {
		t.Fatal("unknown preset loaded")
	}
	split := `{"format":"pqcota-source-map/v1","id":"my-java-scanner","revision":"1","rules":[{"id":"source-properties","componentTypes":["cryptographic-asset"],
	  "locations":{"from":"component","file":{"property":"vendor:sourceFile"},"line":{"property":"vendor:sourceLine"},"lineBase":1}}]}`
	if _, err := ParseMap([]byte(split)); err != nil {
		t.Fatal(err)
	}
}

// 계약 검토 §5의 고정 시험 입력(plans/fixtures/a2-dup-location.cdx.json과 같은 내용).
const dupFixture = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"tools":{"components":[{"type":"application","name":"pqcota-a2-fixture","version":"1"}]}},
 "components":[
  {"type":"cryptographic-asset","bom-ref":"fixture:rsa","name":"RSA",
   "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"pke"}},
   "properties":[{"name":"example:sourceLocation","value":"src/Wrap.cs:12:5"},{"name":"example:note","value":"unrelated"},
     {"name":"example:sourceLocation","value":"src/Wrap.cs:12:5"},{"name":"example:sourceLocation","value":"src/Wrap.cs:30:9"}]},
  {"type":"cryptographic-asset","bom-ref":"fixture:sha-256","name":"SHA-256",
   "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"hash"}},
   "properties":[{"name":"example:sourceLocation","value":"src/Wrap.cs:12:5"}]}
 ]}`

func dupMap(id string, rules ...string) string {
	return `{"format":"pqcota-source-map/v1","id":"` + id + `","revision":"1","rules":[` + strings.Join(rules, ",") + `]}`
}

func dupRule(id, colBase string, each bool) string {
	e := ""
	if each {
		e = `"each":true,`
	}
	return `{"id":"` + id + `","componentTypes":["cryptographic-asset"],"locations":{"from":"component",
	  "combined":{"property":"example:sourceLocation",` + e + `"parser":"path:line:column"},
	  "lineBase":1,"columnBase":` + colBase + `,"columnUnit":"codepoint"}}`
}

func convertWithMap(t *testing.T, raw string, maps ...string) *Interpretation {
	t.Helper()
	var lms []*LoadedMap
	for _, m := range maps {
		lm, err := LoadMap([]byte(m))
		if err != nil {
			t.Fatal(err)
		}
		lms = append(lms, lm)
	}
	in, err := ConvertWith([]byte(raw), DefaultLimits, lms)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func ptrsOf(ls []Location) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.SourcePointers["combined"]
	}
	return out
}

func TestDupFixture(t *testing.T) {
	in := convertWithMap(t, dupFixture, dupMap("fx", dupRule("loc", "1", true)))
	rsa, sha := in.Items[0], in.Items[1]

	// 위치 수와 원본 포인터 — 같은 12:5 둘은 각각 위치다.
	if got := strings.Join(ptrsOf(rsa.Locations), " "); got != "/components/0/properties/0 /components/0/properties/2 /components/0/properties/3" {
		t.Fatalf("RSA pointers %s", got)
	}
	if len(sha.Locations) != 1 || rsa.Locations[0].ID == rsa.Locations[1].ID {
		t.Fatalf("SHA %d locations; RSA ids %s %s", len(sha.Locations), rsa.Locations[0].ID, rsa.Locations[1].ID)
	}
	// 정규화 — 기준 1이라 그대로.
	l := rsa.Locations[2]
	if l.Normalized.Path != "src/Wrap.cs" || *l.Normalized.Line != 30 || *l.Normalized.Column != 9 || l.Reported.Raw != "src/Wrap.cs:30:9" ||
		l.Kind != LocationKindNotSupplied || l.Rule.ID != "fx/loc" || l.Rule.Source != "user" || l.ColumnUnit != "codepoint" {
		t.Fatalf("location %+v", l)
	}
	// 화면 묶기 — RSA 두 줄(12:5 둘, 30:9 하나), SHA-256은 따로.
	if g := groupSizes(GroupLocations(rsa.Locations)); !eqInts(g, []int{2, 1}) {
		t.Fatalf("RSA groups %v", g)
	}
	// 무관한 property는 외부 값으로 남는다.
	if len(rsa.External) != 4 || rsa.External[1].Name != "example:note" {
		t.Fatalf("external %+v", rsa.External)
	}
	if len(Refusals(in, false)) != 0 || in.RuleMatches[0].Components != 2 || in.RuleMatches[0].Locations != 4 {
		t.Fatalf("refusals %v, matches %+v", Refusals(in, false), in.RuleMatches)
	}
}

func TestDupFixtureWithoutEach(t *testing.T) {
	in := convertWithMap(t, dupFixture, dupMap("fx", dupRule("loc", "1", false)))
	rsa := in.Items[0]
	if len(rsa.Locations) != 0 || len(rsa.Diagnostics) != 1 || rsa.Diagnostics[0].Code != DiagMapAmbiguous ||
		!strings.Contains(rsa.Diagnostics[0].Detail, "3 values") {
		t.Fatalf("RSA %+v", rsa)
	}
	// SHA-256은 값이 하나라 모호하지 않다. 그래도 RSA의 모호함 때문에 저장을 거부한다.
	if len(in.Items[1].Locations) != 1 {
		t.Fatalf("SHA %+v", in.Items[1])
	}
	if r := Refusals(in, true); len(r) != 1 || r[0].Code != DiagMapAmbiguous {
		t.Fatalf("refusals %v", r)
	}
}

func TestDupFixtureColumnBaseUnknown(t *testing.T) {
	in := convertWithMap(t, dupFixture, dupMap("fx", dupRule("loc", `"unknown"`, true)))
	l := in.Items[0].Locations[0]
	if l.Normalized.Column != nil || *l.Reported.Column != 5 || *l.Normalized.Line != 12 || l.Normalized.AbsentReason != "column base unknown" {
		t.Fatalf("location %+v", l)
	}
	if g := groupSizes(GroupLocations(in.Items[0].Locations)); !eqInts(g, []int{2, 1}) {
		t.Fatalf("groups %v", g)
	}
	if in.Counts.Diagnostics[DiagColumnBaseUnknown] != 4 || len(Refusals(in, false)) != 0 {
		t.Fatalf("diagnostics %v", in.Counts.Diagnostics)
	}
}

func TestDupFixtureTwoRules(t *testing.T) {
	in := convertWithMap(t, dupFixture, dupMap("fx", dupRule("r1", "1", true), dupRule("r2", "1", true)))
	rsa := in.Items[0]
	if len(rsa.Locations) != 6 {
		t.Fatalf("RSA %d locations", len(rsa.Locations))
	}
	// 같은 포인터라도 규칙이 다르면 위치 id가 다르다.
	if rsa.Locations[0].SourcePointers["combined"] != rsa.Locations[3].SourcePointers["combined"] || rsa.Locations[0].ID == rsa.Locations[3].ID {
		t.Fatalf("ids %s %s", rsa.Locations[0].ID, rsa.Locations[3].ID)
	}
	// 정규화 좌표와 알려진 단위가 같아 묶인다: 12:5 넷, 30:9 둘.
	if g := groupSizes(GroupLocations(rsa.Locations)); !eqInts(g, []int{4, 2}) {
		t.Fatalf("groups %v", g)
	}

	// r2만 열 기준 unknown — 좌표 종류가 달라 묶지 않는다(같은 규칙 안의 12:5 둘씩만).
	in = convertWithMap(t, dupFixture, dupMap("fx", dupRule("r1", "1", true), dupRule("r2", `"unknown"`, true)))
	if g := groupSizes(GroupLocations(in.Items[0].Locations)); !eqInts(g, []int{2, 1, 2, 1}) {
		t.Fatalf("mixed groups %v", g)
	}
}

func TestParseCombined(t *testing.T) {
	type res struct {
		path      string
		line, col int64
		bad       bool
	}
	cases := map[string]res{
		`src/a.cs:12:5`:                   {"src/a.cs", 12, 5, false},
		`C:\src\a.cs:12:5`:                {`C:\src\a.cs`, 12, 5, false},
		`a:b:c.cs:1:2`:                    {"a:b:c.cs", 1, 2, false},
		`src/a.cs:12`:                     {bad: true},
		`:12:5`:                           {bad: true},
		`src/a.cs:x:5`:                    {bad: true},
		`src/a.cs:12:-5`:                  {bad: true},
		`src/a.cs:12:5 `:                  {bad: true},
		`src/a.cs:1:99999999999999999999`: {bad: true},
	}
	for in, want := range cases {
		p, l, c, why := parseCombined(in, ParserPathLineColumn)
		if want.bad != (why != "") {
			t.Errorf("%q: why=%q", in, why)
			continue
		}
		if !want.bad && (p != want.path || l != want.line || c == nil || *c != want.col) {
			t.Errorf("%q: %q %d %v", in, p, l, c)
		}
	}
	if p, l, c, why := parseCombined(`C:\a.cs:7`, ParserPathLine); why != "" || p != `C:\a.cs` || l != 7 || c != nil {
		t.Errorf("path:line: %q %d %v %q", p, l, c, why)
	}
}

const splitInput = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"cryptographic-asset","name":"ok","properties":[{"name":"vendor:file","value":"A.java"},{"name":"vendor:line","value":"0"}]},
 {"type":"cryptographic-asset","name":"dup","properties":[{"name":"vendor:file","value":"A.java"},{"name":"vendor:file","value":"B.java"}]},
 {"type":"cryptographic-asset","name":"noline","properties":[{"name":"vendor:file","value":"A.java"}]},
 {"type":"cryptographic-asset","name":"badline","properties":[{"name":"vendor:file","value":"A.java"},{"name":"vendor:line","value":"12a"}]},
 {"type":"cryptographic-asset","name":"none"},
 {"type":"cryptographic-asset","name":"arr","x":{"locs":[{"f":"C.java","l":3},{"f":"D.java"},{"l":4},"str"]}}
]}`

func TestSplitAndArray(t *testing.T) {
	split := dupMap("split", `{"id":"p","componentTypes":["cryptographic-asset"],"locations":{"from":"component",
	  "file":{"property":"vendor:file"},"line":{"property":"vendor:line"},"lineBase":0}}`)
	arr := dupMap("arr", `{"id":"a","componentTypes":["cryptographic-asset"],"locations":{"from":"component",
	  "array":"/x/locs","file":{"pointer":"/f"},"line":{"pointer":"/l"},"lineBase":1}}`)
	in := convertWithMap(t, splitInput, split, arr)
	codes := func(it Item) string {
		var cs []string
		for _, d := range it.Diagnostics {
			cs = append(cs, d.Code)
		}
		return strings.Join(cs, ",")
	}
	ok := in.Items[0]
	if len(ok.Locations) != 1 || *ok.Locations[0].Normalized.Line != 1 || ok.Locations[0].SourcePointers["file"] != "/components/0/properties/0/value" ||
		ok.Locations[0].SourcePointers["line"] != "/components/0/properties/1/value" {
		t.Fatalf("0-based line: %+v", ok.Locations)
	}
	want := map[int]string{1: DiagMapAmbiguous, 2: DiagMapFieldMissing, 3: DiagMapInvalidLine, 4: ""}
	for i, c := range want {
		if got := codes(in.Items[i]); got != c || len(in.Items[i].Locations) != 0 {
			t.Errorf("%s: diagnostics %q locations %d, want %q", in.Items[i].Reported[0].Value, got, len(in.Items[i].Locations), c)
		}
	}
	a := in.Items[5]
	// 요소마다 위치 하나. 지정한 필드가 빠진 요소는 위치를 만들지 않고 진단한다.
	if len(a.Locations) != 1 || a.Locations[0].SourcePointers["file"] != "/components/5/x/locs/0/f" ||
		a.Locations[0].SourcePointers["line"] != "/components/5/x/locs/0/l" || *a.Locations[0].Normalized.Line != 3 ||
		codes(a) != DiagMapFieldMissing+","+DiagMapFieldMissing+","+DiagMapWrongType {
		t.Fatalf("array: %+v %s", a.Locations, codes(a))
	}
	if in.RuleMatches[0].Components != 4 || in.RuleMatches[1].Components != 1 || in.RuleMatches[1].Locations != 1 {
		t.Fatalf("matches %+v", in.RuleMatches)
	}
}

func TestUnmatchedRuleAndIdentity(t *testing.T) {
	m := dupMap("nomatch", `{"id":"n","componentTypes":["cryptographic-asset"],"locations":{"from":"component","file":{"property":"nope"},"lineBase":1}}`)
	in := convertWithMap(t, dupFixture, m)
	if r := Refusals(in, false); len(r) != 1 || r[0].Code != DiagMapRuleUnmatched || !strings.Contains(r[0].Detail, "nomatch/n") {
		t.Fatalf("refusals %v", r)
	}
	if r := Refusals(in, true); len(r) != 0 {
		t.Fatalf("allowed: %v", r)
	}
	// 결과 ID는 설정 원문에 묶인다. 공백만 다른 설정은 규칙 내용 해시가 같고 결과 ID는 다르다.
	plain := mustConvert(t, dupFixture)
	spaced := convertWithMap(t, dupFixture, strings.Replace(m, `"id":"n"`, `"id" : "n"`, 1))
	if in.ID == plain.ID || in.ID == spaced.ID || in.Rules[1].SHA256 != spaced.Rules[1].SHA256 || in.Maps[0].SHA256 == spaced.Maps[0].SHA256 {
		t.Fatalf("ids: %s %s %s", in.ID, plain.ID, spaced.ID)
	}
	if !in.IDMatches() || len(plain.Maps) != 0 || plain.Maps == nil {
		t.Fatal("id or empty maps")
	}
	// 같은 id의 설정 둘은 받지 않는다.
	a, _ := LoadMap([]byte(m))
	if _, err := ConvertWith([]byte(dupFixture), DefaultLimits, []*LoadedMap{a, a}); !errors.Is(err, ErrBadMap) {
		t.Fatalf("two maps with one id: %v", err)
	}
	// 결정론
	again := convertWithMap(t, dupFixture, m)
	b1, _ := json.Marshal(in)
	b2, _ := json.Marshal(again)
	if string(b1) != string(b2) {
		t.Fatal("not deterministic")
	}
}

func TestLocationLimitAcrossRules(t *testing.T) {
	lm, _ := LoadMap([]byte(dupMap("fx", dupRule("r1", "1", true), dupRule("r2", "1", true))))
	lim := DefaultLimits
	lim.MaxLocationsPerItem = 5
	if _, err := ConvertWith([]byte(dupFixture), lim, []*LoadedMap{lm}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("want ErrLimitExceeded, got %v", err)
	}
}

func TestInvalidCombinedValues(t *testing.T) {
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"x","properties":[
	  {"name":"example:sourceLocation","value":"a.cs:0:5"},{"name":"example:sourceLocation","value":"a.cs:3"},
	  {"name":"example:sourceLocation","value":12}]}]}`
	in := convertWithMap(t, raw, dupMap("fx", dupRule("loc", "1", true)))
	it := in.Items[0]
	if len(it.Locations) != 1 || it.Locations[0].Normalized.Line != nil || it.Locations[0].Diagnostics[0].Code != DiagMapInvalidLine {
		t.Fatalf("line 0 with base 1: %+v", it.Locations)
	}
	if len(it.Diagnostics) != 2 || it.Diagnostics[0].Code != DiagMapUnparsable || it.Diagnostics[1].Code != DiagMapWrongType {
		t.Fatalf("diagnostics %+v", it.Diagnostics)
	}
	if len(Refusals(in, true)) != 3 {
		t.Fatalf("refusals %v", Refusals(in, true))
	}
}

// 로드한 뒤 호출자가 원문 슬라이스를 고쳐도, 적용한 규칙과 결과에 적는 원문 해시는 로드한 원문 그대로다.
func TestLoadedMapIsACopy(t *testing.T) {
	buf := []byte(dupMap("fx", dupRule("loc", "1", true)))
	orig := sha256Hex(buf)
	lm, err := LoadMap(buf)
	if err != nil {
		t.Fatal(err)
	}
	copy(buf, []byte(strings.Replace(string(buf), "example:sourceLocation", "example:sourceLocatioX", 1)))
	got := lm.Raw()
	got[0] = 'X' // 받아 간 사본을 고쳐도 같다
	in, err := ConvertWith([]byte(dupFixture), DefaultLimits, []*LoadedMap{lm})
	if err != nil {
		t.Fatal(err)
	}
	if in.Maps[0].SHA256 != orig || lm.SHA256() != orig || sha256Hex(lm.Raw()) != orig {
		t.Fatalf("map hash changed: %s, want %s", in.Maps[0].SHA256, orig)
	}
	if in.Counts.Locations != 4 {
		t.Fatalf("rules from the edited bytes were applied: %d locations", in.Counts.Locations)
	}
}

// 상한은 위치·진단을 더하는 그 자리에서 건다.
func TestLimitsWhileApplying(t *testing.T) {
	props := func(n int, value string) string {
		var ps []string
		for i := 0; i < n; i++ {
			ps = append(ps, `{"name":"example:sourceLocation","value":"`+value+`"}`)
		}
		return `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"x","properties":[` + strings.Join(ps, ",") + `]}]}`
	}
	lm, _ := LoadMap([]byte(dupMap("fx", dupRule("loc", "1", true))))
	lim := DefaultLimits
	lim.MaxLocationsPerItem, lim.MaxDiagnosticsPerItem = 5, 5

	if in, err := ConvertWith([]byte(props(5, "a.cs:1:1")), lim, []*LoadedMap{lm}); err != nil || in.Counts.Locations != 5 {
		t.Fatalf("exactly at the location limit: %v", err)
	}
	if _, err := ConvertWith([]byte(props(6, "a.cs:1:1")), lim, []*LoadedMap{lm}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("one location over: %v", err)
	}
	// 잘못된 값만 반복 — 위치는 하나도 없지만 진단 상한에 걸린다.
	if in, err := ConvertWith([]byte(props(5, "bad")), lim, []*LoadedMap{lm}); err != nil || len(in.Items[0].Diagnostics) != 5 {
		t.Fatalf("exactly at the diagnostic limit: %v", err)
	}
	if _, err := ConvertWith([]byte(props(100, "bad")), lim, []*LoadedMap{lm}); !errors.Is(err, ErrLimitExceeded) || !strings.Contains(err.Error(), "diagnostics") {
		t.Fatalf("repeated bad values: %v", err)
	}
	// 배열 요소도 같다.
	arr := dupMap("arr", `{"id":"a","componentTypes":["cryptographic-asset"],"locations":{"from":"component","array":"/x","file":{"pointer":"/f"},"lineBase":1}}`)
	alm, _ := LoadMap([]byte(arr))
	els := strings.TrimSuffix(strings.Repeat(`{"f":"a.cs"},`, 6), ",")
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"x","x":[` + els + `]}]}`
	if _, err := ConvertWith([]byte(raw), lim, []*LoadedMap{alm}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("array over the limit: %v", err)
	}
	bad := strings.TrimSuffix(strings.Repeat(`7,`, 6), ",")
	raw = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"x","x":[` + bad + `]}]}`
	if _, err := ConvertWith([]byte(raw), lim, []*LoadedMap{alm}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("array of wrong types over the diagnostic limit: %v", err)
	}
}
