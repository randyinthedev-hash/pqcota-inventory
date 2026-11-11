// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package view — 소스 근거를 사람이 읽는 글로 찍는다. 미리보기(pqcota-cbom-ingest --dry-run)와
// 조회(pqcota-source-evidence)가 같은 모양을 쓴다. 이 출력은 안정 약속을 하지 않는다 — 기계는 --json을 읽는다.
package view

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
)

// 한 번에 보여 줄 만큼. 전부는 --json에 있다.
const (
	previewItems  = 50
	previewGroups = 20
)

// Interpretation — 입력 줄부터 항목까지. size<0이면 크기를 적지 않는다. 미리보기와 조회가 같은 것을 쓴다.
func Interpretation(w io.Writer, in *sourceevidence.Interpretation, size int64) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	if size >= 0 {
		p("input           sha256 %s · %d bytes · CycloneDX %s\n", in.InputSHA256, size, Safe(in.SpecVersion))
	} else {
		p("input           sha256 %s · CycloneDX %s\n", in.InputSHA256, Safe(in.SpecVersion))
	}
	if len(in.Producer) == 0 {
		p("reported tool   none in metadata.tools\n")
	}
	for _, t := range Tools(in.Producer) {
		p("reported tool   %s\n", t)
	}
	rules := make([]string, len(in.Rules))
	for i, r := range in.Rules {
		rules[i] = r.String()
	}
	p("converter       %s · schema %s · rules %s\n", in.ConverterVersion, in.SchemaVersion, strings.Join(rules, ", "))
	p("interpretation  %s\n\n", in.ID)

	c := in.Counts
	p("crypto components %d · with a location %d · without %d · locations %d · other components %d (not read)\n",
		c.Components, c.ItemsWithLocation, c.Components-c.ItemsWithLocation, c.Locations, c.OutOfScope)
	if len(c.Diagnostics) == 0 {
		p("diagnostics       none\n")
	} else {
		codes := make([]string, 0, len(c.Diagnostics))
		for k := range c.Diagnostics {
			codes = append(codes, k)
		}
		sort.Strings(codes)
		parts := make([]string, len(codes))
		for i, k := range codes {
			parts[i] = k + " " + strconv.Itoa(c.Diagnostics[k])
		}
		p("diagnostics       %s\n", strings.Join(parts, " · "))
	}
	for _, d := range in.Diagnostics {
		p("  %s %s %s\n", d.Code, Safe(d.Pointer), Safe(d.Detail))
	}

	for i, it := range in.Items {
		if i == previewItems {
			p("\n… %d more components — use --json for all of them.\n", len(in.Items)-previewItems)
			break
		}
		p("\n%s  %s\n", it.ComponentPointer, itemTitle(it))
		for _, d := range it.Diagnostics {
			p("    ! %s %s %s\n", d.Code, Safe(d.Pointer), Safe(d.Detail))
		}
		if len(it.Locations) == 0 {
			p("    no location reported\n")
			continue
		}
		groups := sourceevidence.GroupLocations(it.Locations)
		for gi, g := range groups {
			if gi == previewGroups {
				p("    … %d more locations — use --json for all of them.\n", len(groups)-previewGroups)
				break
			}
			Group(p, g)
		}
	}
}

// Tools — metadata.tools의 보고값을 도구마다 한 줄로. 원본 포인터의 도구 자리
// (`/metadata/tools/components/0`, `/metadata/tools/services/1`, 옛 배열은 `/metadata/tools/2`)로 가른다.
// 한 줄에 이어 붙이면 판이 어느 도구의 것인지 읽을 수 없다.
func Tools(fs []sourceevidence.Field) []string {
	var keys []string
	by := map[string][]string{}
	for _, f := range fs {
		k := toolKey(f.Pointer)
		if _, ok := by[k]; !ok {
			keys = append(keys, k)
		}
		by[k] = append(by[k], Safe(f.Name)+"="+Safe(f.Value))
	}
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = strings.Join(by[k], " ")
	}
	return out
}

func toolKey(ptr string) string {
	seg := strings.Split(ptr, "/") // "", "metadata", "tools", ("components"|"services"|<i>), <i>, ...
	n := 4
	if len(seg) > 3 && seg[3] != "components" && seg[3] != "services" {
		n = 3
	}
	if len(seg) > n+1 {
		seg = seg[:n+1]
	}
	return strings.Join(seg, "/")
}

func itemTitle(it sourceevidence.Item) string {
	var name string
	var rest []string
	for _, f := range it.Reported {
		switch f.Name {
		case "name":
			name = f.Value
		case "assetType", "oid":
			rest = append(rest, f.Name+"="+f.Value)
		case "algorithmProperties.primitive":
			rest = append(rest, "primitive="+f.Value)
		}
	}
	if name == "" {
		name = "(no name)"
	}
	if len(rest) == 0 {
		return Safe(name)
	}
	return Safe(name) + "  " + Safe(strings.Join(rest, " "))
}

// Group — 위치는 한 줄로 묶고, 위치마다 다를 수 있는 값(규칙·종류·offset·symbol·문맥·진단)은 그 위치의
// 원본 포인터 옆에 적는다. 첫 위치의 값만 머리에 적으면 그 값이 묶인 전부에 해당하는 것처럼 읽힌다.
func Group(p func(string, ...any), g sourceevidence.Group) {
	l := g.Locations[0]
	norm := l.Normalized.Line != nil // 묶기는 정규화한 것과 보고값만 있는 것을 섞지 않는다
	head := "reported location " + coord(l.Reported.Path, l.Reported.Line, l.Reported.Column)
	if norm {
		head = "location " + coord(l.Normalized.Path, l.Normalized.Line, l.Normalized.Column) + " (normalized, 1-based)"
	} else if l.Normalized.AbsentReason != "" {
		head += " (" + Safe(l.Normalized.AbsentReason) + ")"
	}
	if len(g.Locations) > 1 {
		head += fmt.Sprintf(" ×%d", len(g.Locations))
	}
	p("    %s\n", head)
	for _, x := range g.Locations {
		keys := make([]string, 0, len(x.SourcePointers))
		for k := range x.SourcePointers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ptrs := make([]string, len(keys))
		for i, k := range keys {
			ptrs[i] = Safe(x.SourcePointers[k])
		}
		parts := []string{"from " + strings.Join(ptrs, ", "), "rule " + x.Rule.String(), "kind: " + kindLabel(x.Kind)}
		if norm {
			parts = append(parts, "reported "+coord(x.Reported.Path, x.Reported.Line, x.Reported.Column))
		}
		if x.Reported.Offset != nil {
			parts = append(parts, "offset "+strconv.FormatInt(*x.Reported.Offset, 10)+" (unit undefined)")
		}
		if x.Reported.Symbol != "" {
			parts = append(parts, "symbol "+Safe(x.Reported.Symbol))
		}
		if x.Reported.Context != "" {
			parts = append(parts, "context "+Safe(x.Reported.Context))
		}
		p("      %s\n", strings.Join(parts, " · "))
		for _, d := range x.Diagnostics {
			if d.Code == sourceevidence.DiagLineBaseUnknown {
				continue // 머리의 괄호가 이미 말한다
			}
			p("        ! %s %s %s\n", d.Code, Safe(d.Pointer), Safe(d.Detail))
		}
	}
}

func coord(path string, line, col *int64) string {
	s := Safe(path)
	if line != nil {
		s += ":" + strconv.FormatInt(*line, 10)
	}
	if col != nil {
		s += ":" + strconv.FormatInt(*col, 10)
	}
	return s
}

func kindLabel(k string) string {
	if k == sourceevidence.LocationKindNotSupplied {
		return "not supplied"
	}
	return Safe(k)
}

// Safe — 입력에서 온 문자열을 터미널에 찍기 전에 제어 문자·방향 바꿈 문자를 \uXXXX로 바꾼다.
// 경로·문맥은 표시용 데이터다(설계 §6). 원문은 저장소와 --json에 그대로 있다.
func Safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == unicode.ReplacementChar {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
