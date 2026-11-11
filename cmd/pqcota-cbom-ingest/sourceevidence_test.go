// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/store"
)

// 같은 줄을 두 번 보고하되 offset·symbol·문맥이 서로 다른 RSA, 위치 없는 SHA-256, 대상 밖 컴포넌트 하나. 경로에 터미널 제어 문자가 있다.
const sample = `{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"tools":{"services":[{"name":"cbomkit","provider":{"name":"PQCA"}}]}},
 "components":[
  {"type":"cryptographic-asset","name":"RSA-2048",
   "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"pke"}},
   "evidence":{"occurrences":[
     {"location":"src/Wrap.java","line":12,"offset":5,"additionalContext":"Cipher.getInstance"},
     {"location":"src/Wrap.java","line":12,"offset":31,"symbol":"init"},
     {"location":"src/\u001b[31mEvil\u202e.java","line":3}]}},
  {"type":"cryptographic-asset","name":"SHA-256","cryptoProperties":{"assetType":"algorithm"}},
  {"type":"library","name":"bcprov"}
 ]}`

func writeSample(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cbom.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func memOpener(t *testing.T, st store.Store) seStoreOpener {
	return func() (store.Store, func(), storeKind, error) { return st, func() {}, storeMemory, nil }
}

// mustNotOpen — 미리보기·변환 실패에서 저장소를 열면(스키마 생성도 쓰기다) 실패한다.
func mustNotOpen(t *testing.T) seStoreOpener {
	return func() (store.Store, func(), storeKind, error) {
		t.Fatal("the store was opened")
		return nil, nil, "", nil
	}
}

func run(t *testing.T, o seOpts, open seStoreOpener) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runSourceEvidence(o, strings.NewReader(""), &out, &errb, open)
	return code, out.String(), errb.String()
}

func TestParseSourceEvidence(t *testing.T) {
	// 새 플래그가 없으면 기존 경로다 — 인자를 이 파일이 건드리지 않는다.
	for _, args := range [][]string{{"a.json", "web-01"}, {"-", "web-01"}, {"a.json"}, {}} {
		if _, handled, _ := parseSourceEvidence(args); handled {
			t.Errorf("%v: taken by the source evidence path", args)
		}
	}
	ok := map[string]seOpts{
		"a.json web-01 --source-evidence --dry-run": {dryRun: true, input: "a.json", node: "web-01"},
		"--source-evidence --json - web-01":         {json: true, input: "-", node: "web-01"},
		"a.json --source-evidence":                  {input: "a.json"},
	}
	for line, want := range ok {
		got, handled, err := parseSourceEvidence(strings.Fields(line))
		if !handled || err != nil || got != want {
			t.Errorf("%q: %+v handled=%v err=%v, want %+v", line, got, handled, err, want)
		}
	}
	// --dry-run만 주면 기존 경로가 스냅샷을 쓰게 된다 — 멈춰야 한다.
	bad := []string{
		"a.json web-01 --dry-run",
		"a.json web-01 --json",
		// 플래그 철자를 틀리거나 아직 없는 옵션을 주면 기존 경로로 넘어가 스냅샷을 쓰지 않는다.
		"a.json web-01 --source-map map.json",
		"a.json web-01 --source-evidense",
		"a.json web-01 --dryrun",
		"--help",
		"--source-evidence",
		"a b c --source-evidence",
	}
	for _, line := range bad {
		if _, handled, err := parseSourceEvidence(strings.Fields(line)); !handled || err == nil {
			t.Errorf("%q: handled=%v err=%v, want an error", line, handled, err)
		}
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	code, out, errs := run(t, seOpts{dryRun: true, input: writeSample(t, sample), node: "web-01"}, mustNotOpen(t))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{
		"No runtime snapshot is created",
		"target node     web-01 (user-specified; not checked against the scope master)",
		"reported tool   name=cbomkit provider.name=PQCA",
		"crypto components 2 · with a location 1 · without 1 · locations 3 · other components 1 (not read)",
		"    reported location src/Wrap.java:12 (line base unknown) ×2\n" +
			"      from /components/0/evidence/occurrences/0 · rule standard-occurrences@1 · kind: not supplied · offset 5 (unit undefined) · context Cipher.getInstance\n" +
			"      from /components/0/evidence/occurrences/1 · rule standard-occurrences@1 · kind: not supplied · offset 31 (unit undefined) · symbol init\n",
		"/components/0  RSA-2048  assetType=algorithm primitive=pke",
		"no location reported",
		"dry run: nothing was written.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("preview lacks %q\n%s", want, out)
		}
	}
	// 입력의 제어 문자가 터미널에 그대로 나가지 않는다.
	if strings.ContainsAny(out, "\x1b\u202e") || !strings.Contains(out, `src/\u001b[31mEvil\u202e.java:3`) {
		t.Errorf("control characters reached the terminal:\n%q", out)
	}
}

func TestStoreAndReceiveAgain(t *testing.T) {
	st, err := store.NewMemStoreIn("")
	if err != nil {
		t.Fatal(err)
	}
	in := writeSample(t, sample)
	code, out, errs := run(t, seOpts{input: in, node: "web-01"}, memOpener(t, st))
	if code != 0 || !strings.Contains(out, "✓ stored in in-memory (gone when the process exits): receipt #1 · new input: yes · new interpretation: yes") {
		t.Fatalf("first: exit %d\n%s\n%s", code, out, errs)
	}
	code, out, _ = run(t, seOpts{input: in, node: "web-02"}, memOpener(t, st))
	if code != 0 || !strings.Contains(out, "receipt #2 · new input: no · new interpretation: no") ||
		!strings.Contains(out, "only a receipt was added") {
		t.Fatalf("second: exit %d\n%s", code, out)
	}
	if l, _ := st.Interpretations(0); len(l) != 1 {
		t.Fatalf("interpretations %d", len(l))
	}
}

func TestJSONOutput(t *testing.T) {
	in := writeSample(t, sample)
	for _, dry := range []bool{true, false} {
		st, _ := store.NewMemStoreIn("")
		open := memOpener(t, st)
		if dry {
			open = mustNotOpen(t)
		}
		code, out, errs := run(t, seOpts{json: true, dryRun: dry, input: in, node: "web-01"}, open)
		if code != 0 {
			t.Fatalf("dry=%v exit %d: %s", dry, code, errs)
		}
		var got struct {
			Format         string                         `json:"format"`
			DryRun         bool                           `json:"dryRun"`
			Stored         bool                           `json:"stored"`
			StoreKind      string                         `json:"storeKind"`
			Persistent     *bool                          `json:"persistent"`
			TargetNode     string                         `json:"targetNode"`
			Receipt        *store.Receipt                 `json:"receipt"`
			Interpretation *sourceevidence.Interpretation `json:"interpretation"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("dry=%v: not JSON: %v\n%s", dry, err, out)
		}
		if got.Format != "pqcota-source-evidence/v1" || got.DryRun != dry || got.Stored == dry ||
			(got.Receipt == nil) != dry || got.TargetNode != "web-01" || got.Interpretation == nil ||
			len(got.Interpretation.Items) != 2 || got.Persistent == nil || *got.Persistent {
			t.Fatalf("dry=%v: %+v", dry, got)
		}
		if wantKind := map[bool]string{true: "", false: "memory"}[dry]; got.StoreKind != wantKind {
			t.Fatalf("dry=%v: %+v", dry, got)
		}
		if strings.Contains(out, "\x1b") {
			t.Fatalf("raw ESC in JSON output")
		}
		// 원문은 JSON에 그대로 있다(이스케이프만 됐다).
		if got.Interpretation.Items[0].Locations[2].Reported.Path != "src/\x1b[31mEvil\u202e.java" {
			t.Fatalf("JSON changed the reported path: %q", got.Interpretation.Items[0].Locations[2].Reported.Path)
		}
	}
}

type failingStore struct{ store.Store }

func (failingStore) Save(store.Input, *sourceevidence.Interpretation) (store.Receipt, error) {
	return store.Receipt{}, errors.New("disk full")
}

func TestFailuresAreNotReportedAsSuccess(t *testing.T) {
	in := writeSample(t, sample)
	code, out, errs := run(t, seOpts{input: in}, memOpener(t, failingStore{}))
	if code == 0 || strings.Contains(out, "✓") || !strings.Contains(errs, "not stored: disk full") {
		t.Fatalf("save failure: exit %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = run(t, seOpts{input: in}, func() (store.Store, func(), storeKind, error) {
		return nil, nil, "", errors.New("connection refused")
	})
	if code == 0 || out != "" || !strings.Contains(errs, "connection refused") {
		t.Fatalf("open failure: exit %d\n%s\n%s", code, out, errs)
	}
	// 변환이 거부하면 저장소를 열지 않는다.
	code, out, errs = run(t, seOpts{input: writeSample(t, `{"bomFormat":"CycloneDX","specVersion":"1.6"} x`)}, mustNotOpen(t))
	if code == 0 || out != "" || !strings.Contains(errs, "nothing was written") {
		t.Fatalf("bad input: exit %d\n%s\n%s", code, out, errs)
	}
}

// countingReader — 상한을 넘는 입력을 끝까지 읽지 않는지 센다.
type countingReader struct{ n int64 }

func (c *countingReader) Read(p []byte) (int, error) {
	c.n += int64(len(p))
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

func TestReadStopsAtTheLimit(t *testing.T) {
	r := &countingReader{}
	if _, err := readLimited(r, 1000); err == nil {
		t.Fatal("an endless input was accepted")
	}
	if r.n > 1000+64*1024 {
		t.Fatalf("read %d bytes for a 1000-byte limit", r.n)
	}
	b, err := readLimited(strings.NewReader(strings.Repeat("a", 1000)), 1000)
	if err != nil || len(b) != 1000 {
		t.Fatalf("exactly the limit: %d %v", len(b), err)
	}
	if _, err := readLimited(io.MultiReader(strings.NewReader(strings.Repeat("a", 1001))), 1000); err == nil {
		t.Fatal("one byte over the limit was accepted")
	}
}

// 영속 저장이면 JSON이 그렇게 말한다(인메모리와 구분된다).
func TestJSONSaysWhetherPersistent(t *testing.T) {
	st, _ := store.NewMemStoreIn("")
	pg := func() (store.Store, func(), storeKind, error) { return st, func() {}, storePostgres, nil }
	code, out, errs := run(t, seOpts{json: true, input: writeSample(t, sample)}, pg)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got struct {
		Stored     bool   `json:"stored"`
		StoreKind  string `json:"storeKind"`
		Persistent bool   `json:"persistent"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || !got.Stored || got.StoreKind != "postgres" || !got.Persistent {
		t.Fatalf("%+v %v", got, err)
	}
}

// A2 — 계약 검토 §5의 고정 입력과 같은 꼴.
const dupCBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
  {"type":"cryptographic-asset","name":"RSA","cryptoProperties":{"assetType":"algorithm"},
   "properties":[{"name":"example:sourceLocation","value":"src/Wrap.cs:12:5"},{"name":"example:note","value":"unrelated"},
     {"name":"example:sourceLocation","value":"src/Wrap.cs:12:5"},{"name":"example:sourceLocation","value":"src/Wrap.cs:30:9"}]},
  {"type":"cryptographic-asset","name":"SHA-256","cryptoProperties":{"assetType":"algorithm"},
   "properties":[{"name":"example:sourceLocation","value":"src/Wrap.cs:12:5"}]}]}`

func dupMapFile(t *testing.T, each bool, property string) string {
	e := ""
	if each {
		e = `"each":true,`
	}
	body := `{"format":"pqcota-source-map/v1","id":"fx","revision":"1","rules":[{"id":"loc","componentTypes":["cryptographic-asset"],
	  "locations":{"from":"component","combined":{"property":"` + property + `",` + e + `"parser":"path:line:column"},
	  "lineBase":1,"columnBase":1,"columnUnit":"codepoint"}}]}`
	p := filepath.Join(t.TempDir(), "map.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseMappingOptions(t *testing.T) {
	ok := map[string]seOpts{
		"a.json --source-evidence --preset dosai-cyclonedx-location":             {input: "a.json", preset: "dosai-cyclonedx-location"},
		"a.json --source-evidence --preset=x --source-map=m.json":                {input: "a.json", preset: "x", sourceMap: "m.json"},
		"a.json n --source-map m.json --allow-unmatched-rules --source-evidence": {input: "a.json", node: "n", sourceMap: "m.json", allowUnmatched: true},
	}
	for line, want := range ok {
		got, handled, err := parseSourceEvidence(strings.Fields(line))
		if !handled || err != nil || got != want {
			t.Errorf("%q: %+v %v, want %+v", line, got, err, want)
		}
	}
	for _, line := range []string{
		"a.json --source-evidence --preset",
		"a.json --source-evidence --preset --dry-run",
		"a.json --source-evidence --preset=",
		"a.json --source-evidence --preset a --preset b",
		"a.json --source-evidence --source-map -",
		"a.json web-01 --preset x", // --source-evidence 없이
	} {
		if _, handled, err := parseSourceEvidence(strings.Fields(line)); !handled || err == nil {
			t.Errorf("%q: accepted", line)
		}
	}
}

func TestUserMappingStored(t *testing.T) {
	st, _ := store.NewMemStoreIn("")
	mp := dupMapFile(t, true, "example:sourceLocation")
	code, out, errs := run(t, seOpts{input: writeSample(t, dupCBOM), sourceMap: mp}, memOpener(t, st))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"mapping         user fx@1 · sha256 ",
		"rule            fx/loc@1 · matched 2 components · 4 locations",
		"    location src/Wrap.cs:12:5 (normalized, 1-based) ×2\n" +
			"      from /components/0/properties/0 · rule fx/loc@1 · kind: not supplied · reported src/Wrap.cs:12:5\n" +
			"      from /components/0/properties/2 · rule fx/loc@1 · kind: not supplied · reported src/Wrap.cs:12:5\n",
		"✓ stored",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	l, _ := st.Interpretations(0)
	in, _ := st.Interpretation(l[0].ID)
	b, _ := os.ReadFile(mp)
	if got, _ := st.MapRaw(in.Maps[0].SHA256); string(got) != string(b) {
		t.Fatal("the mapping file was not stored as given")
	}
}

func TestMappingErrorsRefuseToStore(t *testing.T) {
	in := writeSample(t, dupCBOM)
	// each 없이 값이 여럿 — 모호함. 미리보기·저장 모두 종료 코드 1, 저장소는 열지 않는다.
	for _, dry := range []bool{true, false} {
		code, out, _ := run(t, seOpts{input: in, sourceMap: dupMapFile(t, false, "example:sourceLocation"), dryRun: dry}, mustNotOpen(t))
		if code != 1 || !strings.Contains(out, "1 mapping problems") || !strings.Contains(out, "map-ambiguous /components/0/properties fx/loc: 3 values") {
			t.Fatalf("dry=%v: exit %d\n%s", dry, code, out)
		}
	}
	code, out, _ := run(t, seOpts{input: in, sourceMap: dupMapFile(t, false, "example:sourceLocation"), json: true}, mustNotOpen(t))
	var got struct {
		Stored   bool                        `json:"stored"`
		Refused  bool                        `json:"refused"`
		Refusals []sourceevidence.Diagnostic `json:"refusals"`
	}
	if err := json.Unmarshal([]byte(out), &got); code != 1 || err != nil || got.Stored || !got.Refused || len(got.Refusals) != 1 {
		t.Fatalf("json: %d %v %+v", code, err, got)
	}

	// 한 번도 맞지 않은 규칙 — 기본 거부, --allow-unmatched-rules면 위치 없이 저장.
	nomatch := dupMapFile(t, true, "no:such")
	code, out, _ = run(t, seOpts{input: in, sourceMap: nomatch}, mustNotOpen(t))
	if code != 1 || !strings.Contains(out, "map-rule-unmatched") || !strings.Contains(out, "--allow-unmatched-rules continues") {
		t.Fatalf("unmatched: exit %d\n%s", code, out)
	}
	st, _ := store.NewMemStoreIn("")
	code, out, _ = run(t, seOpts{input: in, sourceMap: nomatch, allowUnmatched: true}, memOpener(t, st))
	if code != 0 || !strings.Contains(out, "rule            fx/loc@1 · matched 0 components · 0 locations") {
		t.Fatalf("allowed: exit %d\n%s", code, out)
	}
}

func TestBadMappingIsAConfigError(t *testing.T) {
	in := writeSample(t, dupCBOM)
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{"format":"pqcota-source-map/v1","id":"x","revision":"1","rules":[{"id":"r","componentTypes":["cryptographic-asset"],"locations":{"from":"component","file":{"property":"f"},"lineBase":2}}]}`), 0o600)
	code, out, errs := run(t, seOpts{input: in, sourceMap: bad}, mustNotOpen(t))
	if code != 2 || out != "" || !strings.Contains(errs, "lineBase: must be 0, 1") {
		t.Fatalf("bad map: %d %q %q", code, out, errs)
	}
	code, _, errs = run(t, seOpts{input: in, preset: "nope"}, mustNotOpen(t))
	if code != 2 || !strings.Contains(errs, "cdxgen-dotnet-sourcelocation") {
		t.Fatalf("unknown preset: %d %q", code, errs)
	}
	code, _, errs = run(t, seOpts{input: in, sourceMap: filepath.Join(t.TempDir(), "missing.json")}, mustNotOpen(t))
	if code != 2 {
		t.Fatalf("missing map file: %d %q", code, errs)
	}
}

func TestPresetDosai(t *testing.T) {
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
	  {"type":"cryptographic-asset","name":"RSA","cryptoProperties":{"assetType":"algorithm"},"properties":[{"name":"dosai:location","value":"Program.cs:32:9"}]},
	  {"type":"data","name":"op","properties":[{"name":"dosai:location","value":"Program.cs:32:9"}]}]}`
	st, _ := store.NewMemStoreIn("")
	code, out, errs := run(t, seOpts{input: writeSample(t, raw), preset: "dosai-cyclonedx-location"}, memOpener(t, st))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"mapping         preset dosai-cyclonedx-location@1",
		"checked against dosai 5.0.0.0 CycloneDX output",
		"crypto components 1 · with a location 1 · without 0 · locations 1 · other components 1 (not read)",
		"location Program.cs:32 (normalized, 1-based; column base unknown; column unit unknown)\n",
		"reported Program.cs:32:9\n\n",
		"reported Program.cs:32:9",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
}
