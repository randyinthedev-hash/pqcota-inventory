// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sourceevidence

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// 시험 입력은 모두 여기서 직접 쓴 것이다. 외부 도구의 실제 출력은 넣지 않는다.
const std16 = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "metadata": {"tools": {"components": [{"type": "application", "vendor": "Example", "name": "scanner", "version": "2.0"}]}},
  "components": [
    {"type": "library", "name": "bcprov", "components": [
      {"type": "cryptographic-asset", "name": "SHA-256", "bom-ref": "h1",
       "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}}}
    ]},
    {"type": "cryptographic-asset", "name": "RSA-OAEP", "bom-ref": "a1",
     "cryptoProperties": {"assetType": "algorithm", "oid": "1.2.840.113549.1.1.7",
       "algorithmProperties": {"primitive": "key-wrap", "padding": "oaep", "cryptoFunctions": ["encapsulate", "decapsulate"], "nistQuantumSecurityLevel": 0}},
     "properties": [{"name": "tool:readiness", "value": "LOW"}],
     "evidence": {"occurrences": [
       {"location": "src/Wrap.java", "line": 17, "offset": 4, "symbol": "Cipher.getInstance", "additionalContext": "javax.crypto.Cipher#getInstance"},
       {"location": "src/Wrap.java", "line": 17, "symbol": "Cipher.getInstance"},
       {"line": 3},
       {"location": "src/Other.java", "line": "12"},
       {"location": "src/NoLine.java"}
     ]}}
  ]
}`

func mustConvert(t *testing.T, raw string) *Interpretation {
	t.Helper()
	in, err := Convert([]byte(raw), DefaultLimits)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	return in
}

func field(fs []Field, name string) []Field {
	var out []Field
	for _, f := range fs {
		if f.Name == name {
			out = append(out, f)
		}
	}
	return out
}

func TestStandardFields(t *testing.T) {
	in := mustConvert(t, std16)
	if in.SpecVersion != "1.6" || in.Counts.Components != 2 || in.Counts.OutOfScope != 1 {
		t.Fatalf("spec %q components %d outOfScope %d", in.SpecVersion, in.Counts.Components, in.Counts.OutOfScope)
	}
	// 중첩 컴포넌트도 대상이고, 문서 순서(앞선 순회)대로 나온다.
	if in.Items[0].ComponentPointer != "/components/0/components/0" || in.Items[1].ComponentPointer != "/components/1" {
		t.Fatalf("pointers %q %q", in.Items[0].ComponentPointer, in.Items[1].ComponentPointer)
	}
	rsa := in.Items[1]
	if got := field(rsa.Reported, "oid"); len(got) != 1 || got[0].Value != "1.2.840.113549.1.1.7" || got[0].Pointer != "/components/1/cryptoProperties/oid" {
		t.Fatalf("oid %+v", got)
	}
	if got := field(rsa.Reported, "bom-ref"); len(got) != 1 || got[0].Pointer != "/components/1/bom-ref" {
		t.Fatalf("bom-ref %+v", got)
	}
	if got := field(rsa.Reported, "algorithmProperties.cryptoFunctions"); len(got) != 2 || got[1].Pointer != "/components/1/cryptoProperties/algorithmProperties/cryptoFunctions/1" {
		t.Fatalf("cryptoFunctions %+v", got)
	}
	if got := field(rsa.Reported, "algorithmProperties.nistQuantumSecurityLevel"); len(got) != 1 || got[0].Value != "0" {
		t.Fatalf("level %+v", got)
	}
	// 도구가 넣은 평가는 해석하지 않고 외부 값으로 남는다.
	if len(rsa.External) != 1 || rsa.External[0].Name != "tool:readiness" || rsa.External[0].Pointer != "/components/1/properties/0" {
		t.Fatalf("external %+v", rsa.External)
	}
	if len(in.Producer) != 3 || in.Producer[1].Value != "scanner" || in.Producer[1].Pointer != "/metadata/tools/components/0/name" {
		t.Fatalf("producer %+v", in.Producer)
	}
}

func TestPrimitiveNotInSpecIsKept(t *testing.T) {
	// key-wrap은 1.7에서 생겼다. 1.6 문서에 있으면 알리되 보고값은 그대로 둔다.
	in := mustConvert(t, std16)
	rsa := in.Items[1]
	if got := field(rsa.Reported, "algorithmProperties.primitive"); len(got) != 1 || got[0].Value != "key-wrap" {
		t.Fatalf("primitive %+v", got)
	}
	if in.Counts.Diagnostics[DiagPrimitiveNotInVer] != 1 {
		t.Fatalf("diagnostics %+v", in.Counts.Diagnostics)
	}
	in17 := mustConvert(t, strings.Replace(std16, `"specVersion": "1.6"`, `"specVersion": "1.7"`, 1))
	if in17.Counts.Diagnostics[DiagPrimitiveNotInVer] != 0 || in17.SpecVersion != "1.7" {
		t.Fatalf("1.7 diagnostics %+v", in17.Counts.Diagnostics)
	}
}

func TestCurveDeprecatedIn17(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"%s","components":[{"type":"cryptographic-asset","name":"ECDSA",
	  "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"signature","curve":"secp256r1"}}}]}`
	for spec, want := range map[string]int{"1.6": 0, "1.7": 1} {
		in := mustConvert(t, strings.Replace(doc, "%s", spec, 1))
		if in.Counts.Diagnostics[DiagDeprecatedField] != want {
			t.Fatalf("%s: deprecated %d, want %d", spec, in.Counts.Diagnostics[DiagDeprecatedField], want)
		}
		if got := field(in.Items[0].Reported, "algorithmProperties.curve"); len(got) != 1 || got[0].Value != "secp256r1" {
			t.Fatalf("%s: curve not kept %+v", spec, got)
		}
	}
}

func TestOccurrences(t *testing.T) {
	in := mustConvert(t, std16)
	rsa := in.Items[1]
	// 다섯 occurrence 가운데 location이 없는 하나는 위치가 되지 않는다. 나머지 넷은 위치가 된다.
	if len(rsa.Locations) != 4 {
		t.Fatalf("locations %d", len(rsa.Locations))
	}
	l0 := rsa.Locations[0]
	if l0.SourcePointers["occurrence"] != "/components/1/evidence/occurrences/0" || l0.Reported.Path != "src/Wrap.java" ||
		*l0.Reported.Line != 17 || *l0.Reported.Offset != 4 || l0.Reported.Symbol != "Cipher.getInstance" || l0.Reported.Context == "" {
		t.Fatalf("l0 %+v", l0)
	}
	// 표준은 줄의 시작 기준을 정하지 않는다 → 정규화한 줄이 없고 이유가 있다(계약 D1).
	if l0.LineBase != BaseUnknown || l0.Normalized.Line != nil || l0.Normalized.AbsentReason != "line base unknown" {
		t.Fatalf("l0 normalized %+v base %q", l0.Normalized, l0.LineBase)
	}
	if l0.Kind != LocationKindNotSupplied {
		t.Fatalf("kind %q", l0.Kind)
	}
	// 같은 값의 occurrence 둘은 합치지 않는다 — 포인터가 다르고 id도 다르다.
	l1 := rsa.Locations[1]
	if l1.SourcePointers["occurrence"] != "/components/1/evidence/occurrences/1" || l1.ID == l0.ID {
		t.Fatalf("duplicate occurrence merged or same id: %+v", l1)
	}
	// "12"(문자열) 줄은 버리고 알린다. 위치는 남는다.
	l3 := rsa.Locations[2]
	if l3.Reported.Path != "src/Other.java" || l3.Reported.Line != nil || len(l3.Diagnostics) != 1 || l3.Diagnostics[0].Code != DiagInvalidLine {
		t.Fatalf("invalid line %+v", l3)
	}
	// 줄이 없으면 0으로 채우지 않고, 기준 진단도 내지 않는다.
	l4 := rsa.Locations[3]
	if l4.Reported.Line != nil || l4.Normalized.AbsentReason != "" || len(l4.Diagnostics) != 0 {
		t.Fatalf("no-line %+v", l4)
	}
	if in.Counts.Diagnostics[DiagLocationMissing] != 1 || in.Counts.Locations != 4 || in.Counts.ItemsWithLocation != 1 {
		t.Fatalf("counts %+v", in.Counts)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want error
	}{
		"malformed":     {`{"bomFormat":`, ErrMalformed},
		"not object":    {`[]`, ErrNotCycloneDX},
		"not cyclonedx": {`{"bomFormat":"CBOM","specVersion":"1.4-cbom-1.0"}`, ErrNotCycloneDX},
		"spec 1.5":      {`{"bomFormat":"CycloneDX","specVersion":"1.5"}`, ErrUnsupportedSpec},
		"trailing":      {`{"bomFormat":"CycloneDX","specVersion":"1.6"} {}`, ErrTrailingContent},
	}
	for name, c := range cases {
		if _, err := Convert([]byte(c.raw), DefaultLimits); !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", name, err, c.want)
		}
	}
}

func TestLimits(t *testing.T) {
	lim := DefaultLimits
	lim.MaxLocationsPerItem = 3
	if _, err := Convert([]byte(std16), lim); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("occurrence limit: %v", err)
	}
	lim = DefaultLimits
	lim.MaxComponents = 2
	if _, err := Convert([]byte(std16), lim); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("component limit: %v", err)
	}
	lim = DefaultLimits
	lim.MaxDepth = 0
	if _, err := Convert([]byte(std16), lim); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("depth limit: %v", err)
	}
}

func TestDeterministicAndBoundToInput(t *testing.T) {
	a, b := mustConvert(t, std16), mustConvert(t, std16)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatal("same input, different result")
	}
	// 공백 하나만 달라도 입력 바이트가 다르므로 다른 변환 결과다(입력 해시에 묶인다).
	c := mustConvert(t, std16+"\n")
	if c.ID == a.ID || c.Items[1].Locations[0].ID == a.Items[1].Locations[0].ID {
		t.Fatal("different input bytes, same ids")
	}
	if !reflect.DeepEqual(c.Counts, a.Counts) {
		t.Fatal("whitespace changed the counts")
	}
}

func TestEmptyAndNoComponents(t *testing.T) {
	in := mustConvert(t, `{"bomFormat":"CycloneDX","specVersion":"1.7"}`)
	if in.Counts.Components != 0 || len(in.Items) != 0 || in.Items == nil {
		t.Fatalf("%+v", in)
	}
	j, _ := json.Marshal(in)
	if !strings.Contains(string(j), `"items":[]`) {
		t.Fatalf("items should serialize as [] not null: %s", j)
	}
}

// 문서 뒤에는 공백만 허용한다. 잘못된 글자도 「뒤에 붙은 내용」이다(검토 11/10: x·tru·]가 통과했다).
func TestTrailingContent(t *testing.T) {
	base := `{"bomFormat":"CycloneDX","specVersion":"1.6"}`
	for _, tail := range []string{" x", "tru", "]", "{}", " 1", `"s"`, ",", "\x00"} {
		if _, err := Convert([]byte(base+tail), DefaultLimits); !errors.Is(err, ErrTrailingContent) {
			t.Errorf("tail %q: err %v, want ErrTrailingContent", tail, err)
		}
	}
	for _, tail := range []string{"", "\n", " \t\r\n "} {
		if _, err := Convert([]byte(base+tail), DefaultLimits); err != nil {
			t.Errorf("tail %q: %v", tail, err)
		}
	}
}

// integer는 표기가 아니라 값이다(JSON Schema). 부동소수점을 거치지 않고 판단한다.
func TestIntegerNotation(t *testing.T) {
	ok := map[string]int64{"17": 17, "17.0": 17, "1.7e1": 17, "170e-1": 17, "1.70E+1": 17, "0": 0, "-0": 0, "0.0e5": 0,
		"0e-999999999999": 0, "9223372036854775807": 9223372036854775807, "92233720368547758.07e2": 9223372036854775807}
	for s, want := range ok {
		if got, why := nonNegInt(json.Number(s)); why != "" || got != want {
			t.Errorf("%s: got %d %q, want %d", s, got, why, want)
		}
	}
	bad := map[string]string{"1.5": "not an integer", "17e-1": "not an integer", "-1": "negative", "-1.0e0": "negative",
		"9223372036854775808": "out of range", "1e19": "out of range", "1e400": "out of range", "1e9999999999999": "out of range",
		"1e-9999999999999": "not an integer", "abc": "not a number"}
	for s, want := range bad {
		if _, why := nonNegInt(json.Number(s)); why != want {
			t.Errorf("%s: reason %q, want %q", s, why, want)
		}
	}
	if _, why := nonNegInt("12"); why != "expected an integer, got string" {
		t.Errorf("string: %q", why)
	}
	// 변환 경로에서도 17.0이 줄 17이 된다.
	in := mustConvert(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"RSA",
	  "evidence":{"occurrences":[{"location":"a.c","line":17.0,"offset":1.7e1}]}}]}`)
	l := in.Items[0].Locations[0]
	if l.Reported.Line == nil || *l.Reported.Line != 17 || l.Reported.Offset == nil || *l.Reported.Offset != 17 {
		t.Fatalf("line %v offset %v diags %+v", l.Reported.Line, l.Reported.Offset, l.Diagnostics)
	}
}

// CBOMkit은 도구를 서비스로 적고 공급자를 provider.name에 둔다. 같은 구조를 직접 만들어 확인한다.
func TestProducerProvider(t *testing.T) {
	in := mustConvert(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"tools":{"services":[
	  {"provider":{"name":"PQCA"},"name":"CBOMkit"}],
	  "components":[{"type":"application","supplier":{"name":"Acme"},"manufacturer":{"name":"Acme Labs"},"publisher":"Acme Pub","name":"x","version":"1"}]}}}`)
	want := []Field{
		{Name: "supplier.name", Value: "Acme", Pointer: "/metadata/tools/components/0/supplier/name"},
		{Name: "manufacturer.name", Value: "Acme Labs", Pointer: "/metadata/tools/components/0/manufacturer/name"},
		{Name: "provider.name", Value: "PQCA", Pointer: "/metadata/tools/services/0/provider/name"},
		{Name: "name", Value: "CBOMkit", Pointer: "/metadata/tools/services/0/name"},
	}
	for _, w := range want {
		found := false
		for _, f := range in.Producer {
			if f == w {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %+v in %+v", w, in.Producer)
		}
	}
	if got := field(in.Producer, "publisher"); len(got) != 1 || got[0].Value != "Acme Pub" {
		t.Errorf("publisher %+v", got)
	}
	// 옛 배열 꼴도 읽는다.
	old := mustConvert(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"tools":[{"vendor":"V","name":"N","version":"1"}]}}`)
	if len(old.Producer) != 3 || old.Producer[0].Pointer != "/metadata/tools/0/vendor" {
		t.Errorf("legacy %+v", old.Producer)
	}
}

// 필드가 없는 것과 자료형이 틀린 것은 다르다. 틀리면 wrong-type으로 알리고, 「항목 없음」처럼 두지 않는다.
func TestWrongTypes(t *testing.T) {
	diagAt := func(ds []Diagnostic, ptr string) bool {
		for _, d := range ds {
			if d.Code == DiagWrongType && d.Pointer == ptr {
				return true
			}
		}
		return false
	}
	top := mustConvert(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":{},"metadata":{"tools":"x"}}`)
	if !diagAt(top.Diagnostics, "/components") || !diagAt(top.Diagnostics, "/metadata/tools") || top.Counts.Diagnostics[DiagWrongType] != 2 {
		t.Fatalf("top %+v", top.Diagnostics)
	}
	none := mustConvert(t, `{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	if len(none.Diagnostics) != 0 {
		t.Fatalf("absent fields must not be diagnosed: %+v", none.Diagnostics)
	}
	in := mustConvert(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
	  {"type":"cryptographic-asset","name":{"x":1},"cryptoProperties":"x","properties":{},"evidence":[],"components":"x"},
	  {"type":"cryptographic-asset","name":"B","cryptoProperties":{"algorithmProperties":[],"oid":null},
	   "evidence":{"occurrences":{}}},
	  {"type":"cryptographic-asset","name":"C","evidence":{"occurrences":[{"location":5},{"location":"a.c","symbol":3,"line":true}, 7]}},
	  {"type":"library","components":{}}
	]}`)
	a, b, c := in.Items[0], in.Items[1], in.Items[2]
	for _, p := range []string{"/components/0/name", "/components/0/cryptoProperties", "/components/0/properties", "/components/0/evidence", "/components/0/components"} {
		if !diagAt(a.Diagnostics, p) {
			t.Errorf("A missing wrong-type at %s: %+v", p, a.Diagnostics)
		}
	}
	for _, p := range []string{"/components/1/cryptoProperties/algorithmProperties", "/components/1/cryptoProperties/oid", "/components/1/evidence/occurrences"} {
		if !diagAt(b.Diagnostics, p) {
			t.Errorf("B missing wrong-type at %s: %+v", p, b.Diagnostics)
		}
	}
	if !diagAt(c.Diagnostics, "/components/2/evidence/occurrences/0/location") || !diagAt(c.Diagnostics, "/components/2/evidence/occurrences/2") {
		t.Errorf("C item diags %+v", c.Diagnostics)
	}
	if len(c.Locations) != 1 || !diagAt(c.Locations[0].Diagnostics, "/components/2/evidence/occurrences/1/symbol") {
		t.Errorf("C location %+v", c.Locations)
	}
	if c.Locations[0].Reported.Line != nil || c.Locations[0].Diagnostics[0].Code != DiagInvalidLine {
		t.Errorf("C boolean line %+v", c.Locations[0].Diagnostics)
	}
	if !diagAt(in.Diagnostics, "/components/3/components") {
		t.Errorf("library nested components %+v", in.Diagnostics)
	}
}
