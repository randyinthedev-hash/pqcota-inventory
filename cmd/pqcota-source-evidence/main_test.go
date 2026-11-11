// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/store"
)

// 같은 줄을 두 번 보고한 RSA(값은 서로 다름), 위치 없는 SHA-256.
const sampleA = `{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"tools":{"components":[{"type":"application","name":"CryptoScan","version":"1.5.0"}]}},
 "components":[
  {"type":"cryptographic-asset","name":"RSA","cryptoProperties":{"assetType":"algorithm"},
   "evidence":{"occurrences":[{"location":"doc_key.c","line":83,"symbol":"RSA"},{"location":"doc_key.c","line":83,"symbol":"rsa"},
     {"location":"doc_key.c","line":17}]}},
  {"type":"cryptographic-asset","name":"SHA-256","cryptoProperties":{"assetType":"algorithm"}}
 ]}`

const sampleB = `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}`

// 도구 둘 — 판이 어느 도구의 것인지 갈라 보여야 한다.
const sampleC = `{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"tools":{"components":[{"type":"application","name":"dotnet"},{"type":"application","name":"cdxgen","version":"13.7.0"}]}},
 "components":[]}`

func save(t *testing.T, st store.Store, raw, node string) *sourceevidence.Interpretation {
	t.Helper()
	in, err := sourceevidence.Convert([]byte(raw), sourceevidence.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Save(store.Input{NodeID: node, Raw: []byte(raw)}, in); err != nil {
		t.Fatal(err)
	}
	return in
}

func filled(t *testing.T) (*store.MemStore, *sourceevidence.Interpretation, *sourceevidence.Interpretation) {
	t.Helper()
	st, err := store.NewMemStoreIn("acme")
	if err != nil {
		t.Fatal(err)
	}
	a := save(t, st, sampleA, "web-01")
	save(t, st, sampleA, "web-\x1b[2J02")
	save(t, st, sampleA, "")
	b := save(t, st, sampleB, "")
	return st, a, b
}

func runArgs(t *testing.T, st store.Store, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	o, err := parse(args, &errb)
	if err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	code := run(o, st, "acme", &out, &errb)
	return code, out.String(), errb.String()
}

func TestParse(t *testing.T) {
	bad := [][]string{
		{"extra"},
		{"--id", "x", "--input", "y", "--out", "z"},
		{"--input", "abc"},
		{"--out", "f"},
		{"--input", "abc", "--out", "f", "--json"},
		{"--source-map", "m.json"},
	}
	for _, args := range bad {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
	if o, err := parse([]string{"--id", "x", "--json"}, io.Discard); err != nil || o.id != "x" || !o.json {
		t.Errorf("--id x --json: %+v %v", o, err)
	}
}

func TestList(t *testing.T) {
	st, a, b := filled(t)
	code, out, errs := runArgs(t, st)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	// 최근 것(b)이 먼저.
	if ia, ib := strings.Index(out, a.ID), strings.Index(out, b.ID); ia < 0 || ib < 0 || ib > ia {
		t.Fatalf("order: a at %d, b at %d\n%s", ia, ib, out)
	}
	for _, want := range []string{
		"organization acme",
		"CycloneDX 1.6 · reported tool name=CryptoScan version=1.5.0",
		"crypto components 2 · with a location 1 · locations 3 · diagnostics 3",
		`received 3 times · target nodes (user-specified): (not given), web-\u001b[2J02, web-01`,
		"CycloneDX 1.7 · no tool in metadata.tools",
		"received 1 time · target nodes (user-specified): (not given)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("raw ESC in the list")
	}

	code, out, _ = runArgs(t, st, "--json", "--limit", "1")
	var got struct {
		Format, Kind, Organization string
		Interpretations            []struct {
			ID           string   `json:"id"`
			ReceiptCount int      `json:"receiptCount"`
			TargetNodes  []string `json:"targetNodes"`
		}
	}
	if err := json.Unmarshal([]byte(out), &got); code != 0 || err != nil {
		t.Fatalf("json: %d %v\n%s", code, err, out)
	}
	if got.Format != "pqcota-source-evidence/v1" || got.Kind != "interpretations" || got.Organization != "acme" ||
		len(got.Interpretations) != 1 || got.Interpretations[0].ID != b.ID || got.Interpretations[0].ReceiptCount != 1 ||
		len(got.Interpretations[0].TargetNodes) != 1 || got.Interpretations[0].TargetNodes[0] != "" {
		t.Fatalf("%+v", got)
	}
}

func TestListSeparatesTools(t *testing.T) {
	st, _ := store.NewMemStoreIn("acme")
	save(t, st, sampleC, "")
	_, out, _ := runArgs(t, st)
	if !strings.Contains(out, "reported tools name=dotnet | name=cdxgen version=13.7.0") {
		t.Fatalf("tools are not separated\n%s", out)
	}
}

func TestListEmpty(t *testing.T) {
	st, _ := store.NewMemStoreIn("acme")
	code, out, _ := runArgs(t, st)
	if code != 0 || !strings.Contains(out, "nothing stored yet") {
		t.Fatalf("%d\n%s", code, out)
	}
	code, out, _ = runArgs(t, st, "--json")
	if code != 0 || !strings.Contains(out, `"interpretations": []`) {
		t.Fatalf("empty list must be [] not null: %d\n%s", code, out)
	}
}

func TestDetail(t *testing.T) {
	st, a, _ := filled(t)
	code, out, errs := runArgs(t, st, "--id", a.ID)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{
		"#3  ", "target node not given · same input and rules as before",
		`target node web-\u001b[2J02 (user-specified) · same input and rules as before`,
		"target node web-01 (user-specified) · first receipt of this input",
		"interpretation  " + a.ID,
		"    reported location doc_key.c:83 (line base unknown) ×2\n" +
			"      from /components/0/evidence/occurrences/0 · rule standard-occurrences@1 · kind: not supplied · symbol RSA\n" +
			"      from /components/0/evidence/occurrences/1 · rule standard-occurrences@1 · kind: not supplied · symbol rsa\n",
		"no location reported",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail lacks %q\n%s", want, out)
		}
	}
	if strings.Index(out, "web-01 (user-specified)") < strings.Index(out, "#3  ") {
		t.Errorf("receipts are not newest first\n%s", out)
	}

	code, out, _ = runArgs(t, st, "--id", a.ID, "--json")
	var got struct {
		Format, Kind   string
		Interpretation *sourceevidence.Interpretation
		Receipts       []store.Receipt
		DisplayGroups  []struct {
			ItemID string     `json:"itemId"`
			Groups [][]string `json:"groups"`
		} `json:"displayGroups"`
	}
	if err := json.Unmarshal([]byte(out), &got); code != 0 || err != nil {
		t.Fatalf("json: %d %v", code, err)
	}
	locs := a.Items[0].Locations
	if got.Kind != "interpretation" || got.Interpretation.ID != a.ID || len(got.Receipts) != 3 || len(got.DisplayGroups) != 2 ||
		len(got.DisplayGroups[0].Groups) != 2 || len(got.DisplayGroups[0].Groups[0]) != 2 ||
		got.DisplayGroups[0].Groups[0][0] != locs[0].ID || got.DisplayGroups[0].Groups[0][1] != locs[1].ID ||
		len(got.DisplayGroups[1].Groups) != 0 || got.DisplayGroups[1].Groups == nil {
		t.Fatalf("%+v", got)
	}
	// 저장한 결과는 묶이지 않은 그대로다.
	if len(got.Interpretation.Items[0].Locations) != 3 {
		t.Fatalf("stored locations were merged: %d", len(got.Interpretation.Items[0].Locations))
	}
}

func TestDetailOfAnotherOrganization(t *testing.T) {
	_, a, _ := filled(t)
	other, _ := store.NewMemStoreIn("other")
	code, out, errs := runArgs(t, other, "--id", a.ID)
	if code != 1 || out != "" || !strings.Contains(errs, "no interpretation") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

func TestWriteInput(t *testing.T) {
	st, a, _ := filled(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "in.json")
	code, _, errs := runArgs(t, st, "--input", a.InputSHA256, "--out", out)
	if code != 0 || !strings.Contains(errs, "(checked)") {
		t.Fatalf("%d %s", code, errs)
	}
	if b, _ := os.ReadFile(out); string(b) != sampleA {
		t.Fatalf("written input differs")
	}
	// 있는 파일은 덮지 않는다.
	if err := os.WriteFile(out, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runArgs(t, st, "--input", a.InputSHA256, "--out", out); code == 0 {
		t.Fatal("an existing file was overwritten")
	}
	if b, _ := os.ReadFile(out); string(b) != "keep" {
		t.Fatal("the existing file changed")
	}
	if code, _, errs := runArgs(t, st, "--input", strings.Repeat("0", 64), "--out", filepath.Join(dir, "x")); code == 0 || !strings.Contains(errs, "no input") {
		t.Fatalf("unknown sha: %d %s", code, errs)
	}
	// 저장소가 해시와 다른 바이트를 주면 쓰지 않는다.
	bad := filepath.Join(dir, "bad.json")
	if code, _, errs := runArgs(t, tampered{st}, "--input", a.InputSHA256, "--out", bad); code == 0 || !strings.Contains(errs, "does not match") {
		t.Fatalf("tampered: %d %s", code, errs)
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("a file was written from mismatching bytes")
	}
}

type tampered struct{ store.Store }

func (t tampered) InputRaw(sha string) ([]byte, error) {
	b, err := t.Store.InputRaw(sha)
	return append(b, ' '), err
}

// 정확히 100건은 잘린 것이 아니다. 101건째부터 넘쳤다고 적고, 대상 노드가 최근 100건 기준임을 밝힌다.
func TestReceiptsTruncation(t *testing.T) {
	st, _ := store.NewMemStoreIn("acme")
	var a *sourceevidence.Interpretation
	for i := 0; i < 100; i++ {
		a = save(t, st, sampleA, "web-01")
	}
	type detailJSON struct {
		Receipts          []store.Receipt `json:"receipts"`
		ReceiptsTruncated *bool           `json:"receiptsTruncated"`
	}
	check := func(wantMore bool, wantList string) {
		t.Helper()
		_, out, _ := runArgs(t, st)
		if !strings.Contains(out, wantList) {
			t.Errorf("list lacks %q\n%s", wantList, out)
		}
		_, out, _ = runArgs(t, st, "--json")
		var l struct {
			Interpretations []struct {
				ReceiptCount      int  `json:"receiptCount"`
				ReceiptsTruncated bool `json:"receiptsTruncated"`
			}
		}
		if err := json.Unmarshal([]byte(out), &l); err != nil || l.Interpretations[0].ReceiptCount != 100 || l.Interpretations[0].ReceiptsTruncated != wantMore {
			t.Errorf("list json: %+v %v", l, err)
		}
		_, out, _ = runArgs(t, st, "--id", a.ID, "--json")
		var d detailJSON
		if err := json.Unmarshal([]byte(out), &d); err != nil || len(d.Receipts) != 100 || d.ReceiptsTruncated == nil || *d.ReceiptsTruncated != wantMore {
			t.Errorf("detail json: %d receipts, truncated %v, %v", len(d.Receipts), d.ReceiptsTruncated, err)
		}
		_, out, _ = runArgs(t, st, "--id", a.ID)
		if got := strings.Contains(out, "older receipts not shown"); got != wantMore {
			t.Errorf("detail says older receipts not shown = %v, want %v", got, wantMore)
		}
	}
	check(false, "received 100 times · target nodes (user-specified): web-01")
	save(t, st, sampleA, "web-02")
	check(true, "received more than 100 times · target nodes in the latest 100 receipts (user-specified): web-02, web-01")
}
