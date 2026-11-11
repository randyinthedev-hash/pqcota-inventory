// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package view

import (
	"fmt"
	"strings"
	"testing"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
)

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
	Group(func(f string, a ...any) { b.WriteString(fmt.Sprintf(f, a...)) }, g[0])
	want := "    location src/Wrap.cs:12:5 (normalized, 1-based) ×2\n" +
		"      from /components/0/properties/0 · rule zero-based@1 · kind: not supplied · reported src/Wrap.cs:11:4 · symbol Encrypt\n" +
		"      from /components/0/properties/2 · rule one-based@1 · kind: not supplied · reported src/Wrap.cs:12:5\n"
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}

func TestToolsOnePerLine(t *testing.T) {
	fs := []sourceevidence.Field{
		{Name: "name", Value: "dotnet", Pointer: "/metadata/tools/components/0/name"},
		{Name: "name", Value: "cdxgen", Pointer: "/metadata/tools/components/1/name"},
		{Name: "version", Value: "13.7.0", Pointer: "/metadata/tools/components/1/version"},
		{Name: "name", Value: "cbomkit", Pointer: "/metadata/tools/services/0/name"},
		{Name: "provider.name", Value: "PQCA", Pointer: "/metadata/tools/services/0/provider/name"},
		{Name: "vendor", Value: "CSNP", Pointer: "/metadata/tools/0/vendor"},
		{Name: "name", Value: "CryptoScan", Pointer: "/metadata/tools/0/name"},
	}
	got := strings.Join(Tools(fs), "\n")
	want := "name=dotnet\nname=cdxgen version=13.7.0\nname=cbomkit provider.name=PQCA\nvendor=CSNP name=CryptoScan"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestSafe(t *testing.T) {
	cases := map[string]string{
		"src/a.c":       "src/a.c",
		"a\x1b[31mb":    `a\u001b[31mb`,
		"a\u202eb":      `a\u202eb`,
		"line\nbreak\t": `line\u000abreak\u0009`,
		"\xff":          `\ufffd`,
		"한글/경로.java":    "한글/경로.java",
	}
	for in, want := range cases {
		if got := Safe(in); got != want {
			t.Errorf("Safe(%q) = %q, want %q", in, got, want)
		}
	}
}
