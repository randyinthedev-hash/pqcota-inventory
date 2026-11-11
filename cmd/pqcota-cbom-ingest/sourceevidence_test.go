// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
		"a.json web-01 --source-evidence --preset x",
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
		"target node     web-01 (recorded as given; not checked against the scope master)",
		"reported tool   provider.name = PQCA",
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

// 두 규칙이 정규화해 같은 자리로 묶인 위치 — 머리는 정규화한 좌표, 보고값·규칙은 위치마다 적는다(A2 대비).
func TestGroupOfNormalizedLocationsKeepsEachReportedValue(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	mk := func(rule, ptr string, line, col int64, sym string) sourceevidence.Location {
		return sourceevidence.Location{
			Rule:           sourceevidence.RuleRef{Source: "user", ID: rule, Revision: "1"},
			SourcePointers: map[string]string{"combined": ptr},
			Reported:       sourceevidence.ReportedLocation{Path: "src/Wrap.cs", Line: n(line), Column: n(col), Symbol: sym},
			ColumnUnit:     "codepoint",
			Normalized:     sourceevidence.Normalized{Path: "src/Wrap.cs", Line: n(12), Column: n(5)},
			Kind:           sourceevidence.LocationKindNotSupplied,
		}
	}
	g := sourceevidence.GroupLocations([]sourceevidence.Location{
		mk("zero-based", "/components/0/properties/0", 11, 4, "Encrypt"),
		mk("one-based", "/components/0/properties/2", 12, 5, ""),
	})
	if len(g) != 1 {
		t.Fatalf("groups %d", len(g))
	}
	var b strings.Builder
	printGroup(func(f string, a ...any) { b.WriteString(fmt.Sprintf(f, a...)) }, g[0])
	want := "    location src/Wrap.cs:12:5 (normalized, 1-based) ×2\n" +
		"      from /components/0/properties/0 · rule zero-based@1 · kind: not supplied · reported src/Wrap.cs:11:4 · symbol Encrypt\n" +
		"      from /components/0/properties/2 · rule one-based@1 · kind: not supplied · reported src/Wrap.cs:12:5\n"
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}
