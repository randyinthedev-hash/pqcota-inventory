// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

// 소스 근거 경로(설계 v2.1 §5.4·§6, A1). `--source-evidence`를 줄 때만 탄다.
//
//	pqcota-cbom-ingest <cbom.json | -> [target-node-id] --source-evidence [--dry-run] [--json]
//
// 스냅샷을 만들지 않고 노드의 최신 상태를 바꾸지 않는다. 원본·변환 결과·수신 기록을 따로 저장한다.
// 플래그가 없으면 이 파일은 아무것도 하지 않는다 — 기존 경로가 그대로 돈다.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/store"
)

// maxSourceEvidenceInput — 읽기 전부터 거는 원문 상한(설계 §6의 검토 시작값 32 MiB, 확정값 아님).
const maxSourceEvidenceInput = 32 << 20

// OutputFormat — `--json` 출력의 판(계약 검토 §6.1). 같은 판에서는 필드를 더하기만 한다.
const OutputFormat = "pqcota-source-evidence/v1"

// 사람용 출력에서 한 번에 보여 줄 만큼. 전부는 --json에 있다.
const (
	previewItems  = 50
	previewGroups = 20
)

type seOpts struct {
	dryRun bool
	json   bool
	input  string
	node   string
}

// parseSourceEvidence — 새 플래그가 하나도 없으면 handled=false(기존 경로). 플래그는 위치 인자 앞뒤
// 어디에 와도 된다(설계 §5.4의 예가 뒤에 붙인다).
func parseSourceEvidence(args []string) (o seOpts, handled bool, err error) {
	var se bool
	var pos []string
	for _, a := range args {
		switch a {
		case "--source-evidence":
			se, handled = true, true
		case "--dry-run":
			o.dryRun, handled = true, true
		case "--json":
			o.json, handled = true, true
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				pos = append(pos, a) // 새 플래그가 있을 때만 아래에서 거부한다
				continue
			}
			pos = append(pos, a)
		}
	}
	if !handled {
		return o, false, nil
	}
	// --dry-run만 주고 --source-evidence를 빠뜨리면 기존 경로가 스냅샷을 쓴다. 미리보기인 줄 알고
	// 적재하는 일을 막으려고 멈춘다.
	if !se {
		return o, true, errors.New("--dry-run and --json only work with --source-evidence; without it this command writes a runtime snapshot")
	}
	for _, p := range pos {
		if strings.HasPrefix(p, "-") && p != "-" {
			return o, true, fmt.Errorf("unknown option %s", p)
		}
	}
	switch len(pos) {
	case 1:
		o.input = pos[0]
	case 2:
		o.input, o.node = pos[0], pos[1]
	default:
		return o, true, errors.New("usage: pqcota-cbom-ingest <cbom.json | -> [target-node-id] --source-evidence [--dry-run] [--json]")
	}
	return o, true, nil
}

// seStoreOpener — 저장소를 여는 자리. 시험이 바꿔 끼운다. backing은 화면에 적을 이름.
type seStoreOpener func() (st store.Store, closeFn func(), backing string, err error)

func openSourceEvidenceStore() (store.Store, func(), string, error) {
	dsn := os.Getenv("PQCOTA_DSN")
	if dsn == "" {
		m, err := store.NewMemStoreIn(org.FromEnv())
		return m, func() {}, "in-memory (gone when the process exits)", err
	}
	// 기존 경로와 같이 인메모리로 대체하지 않는다 — 영속을 요구했는데 못 들어주면 멈춘다.
	p, err := store.NewPgStoreIn(context.Background(), dsn, org.FromEnv())
	if err != nil {
		return nil, nil, "", err
	}
	return p, p.Close, "Postgres (persistent)", nil
}

// readLimited — 상한을 넘으면 끝까지 읽지 않고 멈춘다.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("input is larger than %d bytes — stopped reading", max)
	}
	return b, nil
}

func readSourceEvidenceInput(name string, stdin io.Reader) ([]byte, error) {
	if name == "-" {
		return readLimited(stdin, maxSourceEvidenceInput)
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimited(f, maxSourceEvidenceInput)
}

type seJSON struct {
	Format         string                         `json:"format"`
	DryRun         bool                           `json:"dryRun"`
	TargetNode     string                         `json:"targetNode"`
	Stored         bool                           `json:"stored"`
	Receipt        *store.Receipt                 `json:"receipt"`
	Interpretation *sourceevidence.Interpretation `json:"interpretation"`
}

// runSourceEvidence — 종료 코드를 돌려준다. 저장에 실패하면 성공을 찍지 않는다(설계 §6).
func runSourceEvidence(o seOpts, stdin io.Reader, stdout, stderr io.Writer, open seStoreOpener) int {
	raw, err := readSourceEvidenceInput(o.input, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "read:", err)
		return 1
	}
	interp, err := sourceevidence.Convert(raw, sourceevidence.DefaultLimits)
	if err != nil {
		fmt.Fprintln(stderr, "✗ not converted, nothing was written:", err)
		return 1
	}

	var rc *store.Receipt
	backing := ""
	if !o.dryRun {
		// 미리보기는 저장소를 열지도 않는다 — 스키마 자동 생성도 DB 쓰기다.
		st, closeFn, b, err := open()
		if err != nil {
			fmt.Fprintln(stderr, "could not open the source evidence store:", err)
			return 1
		}
		defer closeFn()
		r, err := st.Save(store.Input{NodeID: o.node, Raw: raw}, interp)
		if err != nil {
			fmt.Fprintln(stderr, "✗ not stored:", err)
			return 1
		}
		rc, backing = &r, b
	}

	if o.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(seJSON{Format: OutputFormat, DryRun: o.dryRun, TargetNode: o.node,
			Stored: rc != nil, Receipt: rc, Interpretation: interp}); err != nil {
			fmt.Fprintln(stderr, "write:", err)
			return 1
		}
		return 0
	}
	printPreview(stdout, o, int64(len(raw)), interp)
	if rc == nil {
		fmt.Fprintln(stdout, "\ndry run: nothing was written.")
		return 0
	}
	fmt.Fprintf(stdout, "\n✓ stored in %s: receipt #%d · new input: %s · new interpretation: %s\n",
		backing, rc.Seq, yesNo(rc.NewInput), yesNo(rc.NewInterpretation))
	if !rc.NewInterpretation {
		fmt.Fprintln(stdout, "  the same input and rules were received before — only a receipt was added.")
	}
	return 0
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func printPreview(w io.Writer, o seOpts, size int64, in *sourceevidence.Interpretation) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("source evidence — locations the CBOM reported, for review. No runtime snapshot is created.\n\n")
	p("input           sha256 %s · %d bytes · CycloneDX %s\n", in.InputSHA256, size, safe(in.SpecVersion))
	if o.node != "" {
		p("target node     %s (recorded as given; not checked against the scope master)\n", safe(o.node))
	} else {
		p("target node     not given\n")
	}
	if len(in.Producer) == 0 {
		p("reported tool   none in metadata.tools\n")
	}
	for _, f := range in.Producer {
		p("reported tool   %s = %s\n", safe(f.Name), safe(f.Value))
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
		p("  %s %s %s\n", d.Code, safe(d.Pointer), safe(d.Detail))
	}

	for i, it := range in.Items {
		if i == previewItems {
			p("\n… %d more components — use --json for all of them.\n", len(in.Items)-previewItems)
			break
		}
		p("\n%s  %s\n", it.ComponentPointer, itemTitle(it))
		for _, d := range it.Diagnostics {
			p("    ! %s %s %s\n", d.Code, safe(d.Pointer), safe(d.Detail))
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
			printGroup(p, g)
		}
	}
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
		return safe(name)
	}
	return safe(name) + "  " + safe(strings.Join(rest, " "))
}

func printGroup(p func(string, ...any), g sourceevidence.Group) {
	l := g.Locations[0]
	pos := l.Reported.Path
	if l.Reported.Line != nil {
		pos += ":" + strconv.FormatInt(*l.Reported.Line, 10)
	}
	if l.Reported.Column != nil {
		pos += ":" + strconv.FormatInt(*l.Reported.Column, 10)
	}
	note := ""
	if l.Normalized.AbsentReason != "" {
		note = " (" + l.Normalized.AbsentReason + ")"
	}
	times := ""
	if len(g.Locations) > 1 {
		times = fmt.Sprintf(" ×%d", len(g.Locations))
	}
	p("    reported location %s%s%s · kind: %s · rule %s\n", safe(pos), note, times, kindLabel(l.Kind), l.Rule.String())
	if l.Reported.Offset != nil {
		p("      offset %d (unit and base not defined; kept as reported)\n", *l.Reported.Offset)
	}
	if l.Reported.Symbol != "" {
		p("      symbol  %s\n", safe(l.Reported.Symbol))
	}
	if l.Reported.Context != "" {
		p("      context %s\n", safe(l.Reported.Context))
	}
	for _, x := range g.Locations {
		keys := make([]string, 0, len(x.SourcePointers))
		for k := range x.SourcePointers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p("      from %s\n", safe(x.SourcePointers[k]))
		}
		for _, d := range x.Diagnostics {
			if d.Code == sourceevidence.DiagLineBaseUnknown {
				continue // 위의 괄호가 이미 말한다
			}
			p("      ! %s %s %s\n", d.Code, safe(d.Pointer), safe(d.Detail))
		}
	}
}

func kindLabel(k string) string {
	if k == sourceevidence.LocationKindNotSupplied {
		return "not supplied"
	}
	return safe(k)
}

// safe — 입력에서 온 문자열을 터미널에 찍기 전에 제어 문자·방향 바꿈 문자를 \uXXXX로 바꾼다.
// 경로·문맥은 표시용 데이터다(설계 §6). 원문은 저장소와 --json에 그대로 있다.
func safe(s string) string {
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
