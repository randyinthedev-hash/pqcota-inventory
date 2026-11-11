// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-source-evidence — `pqcota-cbom-ingest --source-evidence`가 저장한 소스 근거를 조회한다.
// 읽기 전용이다. 런타임 스냅샷은 보지 않는다(그것은 pqcota-inventory).
//
//	pqcota-source-evidence [--limit N] [--json]                # 변환 결과 목록(최근 것부터)
//	pqcota-source-evidence --id <interpretation-id> [--json]    # 한 변환 결과의 항목·위치·수신 기록
//	pqcota-source-evidence --input <sha256> --out <file>        # 받은 원본을 그대로 파일로(있는 파일은 덮지 않는다)
//	pqcota-source-evidence --map <sha256> --out <file>          # 변환에 쓴 매핑 설정 원문을 그대로 파일로
//	pqcota-source-evidence --presets [--json]                   # 내장 프리셋 목록(DB를 열지 않는다)
//
// env PQCOTA_DSN 필수 — pqcota-cbom-ingest가 쓴 저장소. 인메모리 저장은 프로세스 사이에 남지 않는다.
// 대상 노드는 사용자가 적재할 때 준 이름 그대로다. 스코프 마스터와 대조하지 않았다.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/store"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/view"
)

// OutputFormat — `--json`의 판. pqcota-cbom-ingest와 같은 판을 쓰고 kind로 가른다(계약 검토 §6.1).
const OutputFormat = "pqcota-source-evidence/v1"

type opts struct {
	id, input, mapSHA, out string
	limit                  int
	json, presets          bool
}

func parse(args []string, stderr io.Writer) (opts, error) {
	var o opts
	fs := flag.NewFlagSet("pqcota-source-evidence", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.id, "id", "", "show one interpretation — items, locations and receipts")
	fs.StringVar(&o.input, "input", "", "sha256 of a received input to write out as it was received (needs --out)")
	fs.StringVar(&o.mapSHA, "map", "", "sha256 of a mapping file used for a conversion, to write out as stored (needs --out)")
	fs.StringVar(&o.out, "out", "", "file to write the input or mapping to; an existing file is not overwritten")
	fs.BoolVar(&o.presets, "presets", false, "list the built-in mapping presets (does not open the database)")
	fs.IntVar(&o.limit, "limit", 0, "how many interpretations to list (default 100)")
	fs.BoolVar(&o.json, "json", false, "machine-readable output ("+OutputFormat+")")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	modes := 0
	for _, on := range []bool{o.id != "", o.input != "", o.mapSHA != "", o.presets} {
		if on {
			modes++
		}
	}
	raw := o.input != "" || o.mapSHA != ""
	switch {
	case fs.NArg() > 0:
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case modes > 1:
		return o, errors.New("use only one of --id, --input, --map, --presets")
	case raw && o.out == "":
		return o, errors.New("--input and --map need --out <file>: the bytes are written as stored and are not printed to the terminal")
	case o.out != "" && !raw:
		return o, errors.New("--out only works with --input or --map")
	case raw && o.json:
		return o, errors.New("--json does not apply to --input or --map")
	}
	return o, nil
}

func main() {
	o, err := parse(os.Args[1:], os.Stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(2)
	}
	if o.presets {
		if err := presets(o, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	dsn := os.Getenv("PQCOTA_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "PQCOTA_DSN is required — it must point at the same Postgres that pqcota-cbom-ingest --source-evidence wrote to.")
		fmt.Fprintln(os.Stderr, "(the in-memory store is not shared across processes)")
		os.Exit(2)
	}
	// 조회는 스키마를 만들지 않는다 — 있는지만 본다.
	st, err := store.OpenPgStoreIn(context.Background(), dsn, org.FromEnv())
	if errors.Is(err, history.ErrSchemaMissing) {
		fmt.Fprintln(os.Stderr, "no source evidence tables in this database:", err)
		fmt.Fprintln(os.Stderr, "(nothing was stored here with pqcota-cbom-ingest --source-evidence yet, or PQCOTA_DSN points at another database; this command does not create them)")
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "connecting to Postgres:", err)
		os.Exit(1)
	}
	code := run(o, st, string(st.Org()), os.Stdout, os.Stderr)
	st.Close()
	os.Exit(code)
}

func run(o opts, st store.Store, organization string, stdout, stderr io.Writer) int {
	var err error
	switch {
	case o.input != "":
		err = writeRaw(st.InputRaw, "input", o.input, o.out, stderr)
	case o.mapSHA != "":
		err = writeRaw(st.MapRaw, "mapping", o.mapSHA, o.out, stderr)
	case o.id != "":
		err = detail(st, o, organization, stdout)
	default:
		err = list(st, o, organization, stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// listEntry — 목록 한 줄. Summary에 수신 요약을 더한다.
type listEntry struct {
	store.Summary
	ReceiptCount      int      `json:"receiptCount"`      // 본 수신 기록 수(넘쳤으면 receiptScan)
	ReceiptsTruncated bool     `json:"receiptsTruncated"` // 그보다 더 있다
	TargetNodes       []string `json:"targetNodes"`       // 본 수신 기록의 사용자 지정 이름. 빈 값은 「지정하지 않음」
}

// receiptScan — 한 결과당 보는 수신 기록 수. 하나 더 읽어 넘쳤는지 안다.
const receiptScan = 100

// recentReceipts — 최근 receiptScan건과, 그보다 더 있는지.
func recentReceipts(st store.Store, id string) ([]store.Receipt, bool, error) {
	rs, err := st.ReceiptsOf(id, receiptScan+1)
	if err != nil {
		return nil, false, fmt.Errorf("reading receipts: %w", err)
	}
	if rs == nil {
		rs = []store.Receipt{}
	}
	if len(rs) > receiptScan {
		return rs[:receiptScan], true, nil
	}
	return rs, false, nil
}

func list(st store.Store, o opts, organization string, w io.Writer) error {
	sums, err := st.Interpretations(o.limit)
	if err != nil {
		return fmt.Errorf("reading interpretations: %w", err)
	}
	entries := make([]listEntry, 0, len(sums))
	for _, s := range sums {
		rs, more, err := recentReceipts(st, s.ID)
		if err != nil {
			return err
		}
		e := listEntry{Summary: s, ReceiptCount: len(rs), ReceiptsTruncated: more, TargetNodes: []string{}}
		seen := map[string]bool{}
		for _, r := range rs {
			if !seen[r.NodeID] {
				seen[r.NodeID] = true
				e.TargetNodes = append(e.TargetNodes, r.NodeID)
			}
		}
		entries = append(entries, e)
	}
	if o.json {
		return writeJSON(w, map[string]any{
			"format": OutputFormat, "kind": "interpretations", "organization": organization,
			"interpretations": entries,
		})
	}

	fmt.Fprintf(w, "source evidence — stored interpretations, newest first · organization %s\n", view.Safe(organization))
	if len(entries) == 0 {
		fmt.Fprintln(w, "\nnothing stored yet — pqcota-cbom-ingest <cbom.json> [node] --source-evidence stores one.")
		return nil
	}
	for _, e := range entries {
		c := e.Counts
		diags := 0
		for _, n := range c.Diagnostics {
			diags += n
		}
		fmt.Fprintf(w, "\n%s\n", e.ID)
		fmt.Fprintf(w, "    stored %s · CycloneDX %s · %s\n", e.CreatedAt.Format("2006-01-02 15:04:05Z"),
			view.Safe(e.SpecVersion), tools(e.Producer))
		fmt.Fprintf(w, "    input sha256 %s\n", e.InputSHA256)
		fmt.Fprintf(w, "    %s\n", mapsLine(e.Maps))
		fmt.Fprintf(w, "    crypto components %d · with a location %d · locations %d · diagnostics %d\n",
			c.Components, c.ItemsWithLocation, c.Locations, diags)
		if e.ReceiptsTruncated {
			fmt.Fprintf(w, "    received more than %d times · target nodes in the latest %d receipts (user-specified): %s\n",
				receiptScan, receiptScan, nodeList(e.TargetNodes))
		} else {
			times := "times"
			if e.ReceiptCount == 1 {
				times = "time"
			}
			fmt.Fprintf(w, "    received %d %s · target nodes (user-specified): %s\n", e.ReceiptCount, times, nodeList(e.TargetNodes))
		}
	}
	if o.limit <= 0 && len(entries) == 100 || o.limit > 0 && len(entries) == o.limit {
		fmt.Fprintf(w, "\nshowing %d — use --limit for more.\n", len(entries))
	}
	return nil
}

func tools(fs []sourceevidence.Field) string {
	if len(fs) == 0 {
		return "no tool in metadata.tools"
	}
	ts := view.Tools(fs)
	if len(ts) == 1 {
		return "reported tool " + ts[0]
	}
	return "reported tools " + strings.Join(ts, " | ")
}

func mapsLine(ms []sourceevidence.MapRef) string {
	if len(ms) == 0 {
		return "standard fields only (no mapping)"
	}
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = view.Safe(m.Source) + " " + view.Safe(m.ID) + "@" + view.Safe(m.Revision)
	}
	return "mapping " + strings.Join(parts, ", ")
}

func nodeList(ns []string) string {
	out := make([]string, len(ns))
	for i, n := range ns {
		if n == "" {
			out[i] = "(not given)"
		} else {
			out[i] = view.Safe(n)
		}
	}
	return strings.Join(out, ", ")
}

// itemGroups — 화면에서 묶은 위치의 ID. 저장한 결과는 묶지 않으므로 --json은 묶음을 따로 알린다.
type itemGroups struct {
	ItemID string     `json:"itemId"`
	Groups [][]string `json:"groups"` // 묶음마다 위치 ID, 결과 안의 순서대로
}

func detail(st store.Store, o opts, organization string, w io.Writer) error {
	in, err := st.Interpretation(o.id)
	if err != nil {
		return fmt.Errorf("reading interpretation: %w", err)
	}
	if in == nil {
		return fmt.Errorf("no interpretation %s in organization %s", view.Safe(o.id), view.Safe(organization))
	}
	rs, more, err := recentReceipts(st, in.ID)
	if err != nil {
		return err
	}
	if o.json {
		groups := make([]itemGroups, 0, len(in.Items))
		for _, it := range in.Items {
			ig := itemGroups{ItemID: it.ID, Groups: [][]string{}}
			for _, g := range sourceevidence.GroupLocations(it.Locations) {
				ids := make([]string, len(g.Locations))
				for i, l := range g.Locations {
					ids[i] = l.ID
				}
				ig.Groups = append(ig.Groups, ids)
			}
			groups = append(groups, ig)
		}
		return writeJSON(w, map[string]any{
			"format": OutputFormat, "kind": "interpretation", "organization": organization,
			"interpretation": in, "receipts": rs, "receiptsTruncated": more, "displayGroups": groups,
		})
	}

	fmt.Fprintf(w, "source evidence — locations the CBOM reported, for review · organization %s\n\n", view.Safe(organization))
	fmt.Fprintf(w, "receipts (newest first; target node is the name given at ingest, not checked against the scope master)\n")
	for _, r := range rs {
		node := "not given"
		if r.NodeID != "" {
			node = view.Safe(r.NodeID) + " (user-specified)"
		}
		what := "same input and rules as before"
		switch {
		case r.NewInput:
			what = "first receipt of this input"
		case r.NewInterpretation:
			what = "input seen before, new interpretation"
		}
		fmt.Fprintf(w, "    #%d  %s  target node %s · %s\n", r.Seq, r.ReceivedAt.Format("2006-01-02 15:04:05Z"), node, what)
	}
	if more {
		fmt.Fprintf(w, "    … older receipts not shown (only the latest %d)\n", receiptScan)
	}
	fmt.Fprintln(w)
	view.Interpretation(w, in, -1)
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeRaw — 저장된 바이트(원본·설정)를 그대로 파일에 쓴다. 터미널에는 찍지 않는다(제어 문자가 그대로 나간다).
// 해시를 다시 재서 저장소가 준 바이트가 그것인지 확인한 뒤에 쓴다.
func writeRaw(fetch func(string) ([]byte, error), what, sha, out string, stderr io.Writer) error {
	raw, err := fetch(sha)
	if err != nil {
		return fmt.Errorf("reading %s: %w", what, err)
	}
	if raw == nil {
		return fmt.Errorf("no %s with sha256 %s in this organization", what, view.Safe(sha))
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != sha {
		return fmt.Errorf("stored %s does not match its sha256 (got %s) — not written", what, got)
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, bytes.NewReader(raw)); err != nil {
		f.Close()
		os.Remove(out) // 반쯤 쓴 파일을 원본처럼 남기지 않는다
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(out)
		return err
	}
	fmt.Fprintf(stderr, "wrote %d bytes to %s · sha256 %s (checked)\n", len(raw), view.Safe(out), sha)
	return nil
}

// presets — 내장 프리셋 목록. 어느 도구의 어느 판으로 확인했는지 함께 보인다.
func presets(o opts, w io.Writer) error {
	ps := sourceevidence.Presets()
	if o.json {
		type entry struct {
			ID           string `json:"id"`
			Revision     string `json:"revision"`
			VerifiedWith string `json:"verifiedWith"`
			Note         string `json:"note"`
		}
		es := make([]entry, len(ps))
		for i, p := range ps {
			es[i] = entry{p.ID, p.Revision, p.VerifiedWith, p.Note}
		}
		return writeJSON(w, map[string]any{"format": OutputFormat, "kind": "presets", "presets": es})
	}
	fmt.Fprintln(w, "built-in mapping presets — use with pqcota-cbom-ingest ... --source-evidence --preset <id>")
	for _, p := range ps {
		fmt.Fprintf(w, "\n%s@%s\n    checked against %s only; other versions are not promised\n    %s\n", p.ID, p.Revision, p.VerifiedWith, p.Note)
	}
	return nil
}
