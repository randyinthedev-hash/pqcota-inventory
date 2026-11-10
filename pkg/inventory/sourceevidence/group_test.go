// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sourceevidence

import "testing"

func i64(n int64) *int64 { return &n }

var (
	ruleA = RuleRef{Source: "user", ID: "a", Revision: "1", SHA256: "aa"}
	ruleB = RuleRef{Source: "user", ID: "b", Revision: "1", SHA256: "bb"}
)

// loc — 보고값 path:line:col, 정규화 여부·단위를 지정한 위치.
func loc(r RuleRef, ptr string, line, col int64, normalized bool, unit string) Location {
	l := Location{Rule: r, SourcePointers: map[string]string{"combined": ptr},
		Reported: ReportedLocation{Path: "src/Wrap.cs", Line: i64(line), Column: i64(col)}, ColumnUnit: unit,
		Normalized: Normalized{Path: "src/Wrap.cs"}}
	if normalized {
		l.Normalized.Line, l.Normalized.Column = i64(line), i64(col)
	}
	return l
}

func groupSizes(gs []Group) []int {
	out := make([]int, len(gs))
	for i, g := range gs {
		out[i] = len(g.Locations)
	}
	return out
}

func eqInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGroupLocations(t *testing.T) {
	cases := []struct {
		name string
		locs []Location
		want []int
	}{
		{"same rule, same reported, base unknown", []Location{
			loc(ruleA, "/p/0", 12, 5, false, "unknown"), loc(ruleA, "/p/2", 12, 5, false, "unknown"), loc(ruleA, "/p/3", 30, 9, false, "unknown")}, []int{2, 1}},
		{"different rules, both unknown: not the same basis", []Location{
			loc(ruleA, "/p/0", 12, 5, false, "unknown"), loc(ruleB, "/p/0", 12, 5, false, "unknown")}, []int{1, 1}},
		{"different rules, both normalized, same known unit", []Location{
			loc(ruleA, "/p/0", 12, 5, true, "codepoint"), loc(ruleB, "/p/0", 12, 5, true, "codepoint")}, []int{2}},
		{"different rules, normalized but different units", []Location{
			loc(ruleA, "/p/0", 12, 5, true, "codepoint"), loc(ruleB, "/p/0", 12, 5, true, "utf16")}, []int{1, 1}},
		{"different rules, normalized but unit unknown", []Location{
			loc(ruleA, "/p/0", 12, 5, true, "unknown"), loc(ruleB, "/p/0", 12, 5, true, "unknown")}, []int{1, 1}},
		{"normalized and reported-only are never mixed", []Location{
			loc(ruleA, "/p/0", 12, 5, true, "codepoint"), loc(ruleA, "/p/2", 12, 5, false, "unknown")}, []int{1, 1}},
		{"same rule, different line", []Location{
			loc(ruleA, "/p/0", 12, 5, false, "unknown"), loc(ruleA, "/p/1", 13, 5, false, "unknown")}, []int{1, 1}},
	}
	for _, c := range cases {
		if got := groupSizes(GroupLocations(c.locs)); !eqInts(got, c.want) {
			t.Errorf("%s: groups %v, want %v", c.name, got, c.want)
		}
	}
}

// 표준 규칙의 같은 occurrence 둘은 한 줄로 보이고, 두 원본 포인터가 모두 남는다.
func TestGroupStandardDuplicates(t *testing.T) {
	in := mustConvert(t, std16)
	gs := GroupLocations(in.Items[1].Locations)
	if !eqInts(groupSizes(gs), []int{2, 1, 1}) {
		t.Fatalf("groups %v", groupSizes(gs))
	}
	p := []string{gs[0].Locations[0].SourcePointers["occurrence"], gs[0].Locations[1].SourcePointers["occurrence"]}
	if p[0] != "/components/1/evidence/occurrences/0" || p[1] != "/components/1/evidence/occurrences/1" {
		t.Fatalf("pointers %v", p)
	}
}
