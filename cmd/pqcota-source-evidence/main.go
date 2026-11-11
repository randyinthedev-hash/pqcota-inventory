// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-source-evidence — `pqcota-cbom-ingest --source-evidence`가 저장한 소스 근거를 조회한다.
// 읽기 전용이다. 런타임 스냅샷은 보지 않는다(그것은 pqcota-inventory).
//
//	pqcota-source-evidence [--limit N] [--json]                # 변환 결과 목록(최근 것부터)
//	pqcota-source-evidence --id <interpretation-id> [--json]    # 한 변환 결과의 항목·위치·수신 기록
//	pqcota-source-evidence --input <sha256> --out <file>        # 받은 원본을 그대로 파일로(있는 파일은 덮지 않는다)
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
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/store"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/view"
)

// OutputFormat — `--json`의 판. pqcota-cbom-ingest와 같은 판을 쓰고 kind로 가른다(계약 검토 §6.1).
const OutputFormat = "pqcota-source-evidence/v1"

type opts struct {
	id, input, out string
	limit          int
	json           bool
}

func parse(args []string, stderr io.Writer) (opts, error) {
	var o opts
	fs := flag.NewFlagSet("pqcota-source-evidence", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.id, "id", "", "show one interpretation — items, locations and receipts")
	fs.StringVar(&o.input, "input", "", "sha256 of a received input to write out as it was received (needs --out)")
	fs.StringVar(&o.out, "out", "", "file to write the input to; an existing file is not overwritten")
	fs.IntVar(&o.limit, "limit", 0, "how many interpretations to list (default 100)")
	fs.BoolVar(&o.json, "json", false, "machine-readable output ("+OutputFormat+")")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	switch {
	case fs.NArg() > 0:
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case o.id != "" && o.input != "":
		return o, errors.New("--id and --input cannot be used together")
	case o.input != "" && o.out == "":
		return o, errors.New("--input needs --out <file>: the input is written as received and is not printed to the terminal")
	case o.out != "" && o.input == "":
		return o, errors.New("--out only works with --input")
	case o.input != "" && o.json:
		return o, errors.New("--json does not apply to --input")
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
	dsn := os.Getenv("PQCOTA_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "PQCOTA_DSN is required — it must point at the same Postgres that pqcota-cbom-ingest --source-evidence wrote to.")
		fmt.Fprintln(os.Stderr, "(the in-memory store is not shared across processes)")
		os.Exit(2)
	}
	st, err := store.NewPgStoreIn(context.Background(), dsn, org.FromEnv())
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
		err = writeInput(st, o.input, o.out, stderr)
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
	ReceiptCount     int      `json:"receiptCount"`
	ReceiptsTruncate bool     `json:"receiptsTruncated"` // 수신 기록이 상한보다 많아 다 세지 않았다
	TargetNodes      []string `json:"targetNodes"`       // 사용자가 준 이름. 빈 값은 「지정하지 않음」
}

// receiptScan — 목록에서 한 결과당 보는 수신 기록 수.
const receiptScan = 100

func list(st store.Store, o opts, organization string, w io.Writer) error {
	sums, err := st.Interpretations(o.limit)
	if err != nil {
		return fmt.Errorf("reading interpretations: %w", err)
	}
	entries := make([]listEntry, 0, len(sums))
	for _, s := range sums {
		rs, err := st.ReceiptsOf(s.ID, receiptScan)
		if err != nil {
			return fmt.Errorf("reading receipts: %w", err)
		}
		e := listEntry{Summary: s, ReceiptCount: len(rs), ReceiptsTruncate: len(rs) == receiptScan, TargetNodes: []string{}}
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
		fmt.Fprintf(w, "    crypto components %d · with a location %d · locations %d · diagnostics %d\n",
			c.Components, c.ItemsWithLocation, c.Locations, diags)
		n := fmt.Sprint(e.ReceiptCount)
		if e.ReceiptsTruncate {
			n += "+"
		}
		times := "times"
		if n == "1" {
			times = "time"
		}
		fmt.Fprintf(w, "    received %s %s · target nodes (user-specified): %s\n", n, times, nodeList(e.TargetNodes))
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
	rs, err := st.ReceiptsOf(in.ID, 0)
	if err != nil {
		return fmt.Errorf("reading receipts: %w", err)
	}
	if rs == nil {
		rs = []store.Receipt{}
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
			"interpretation": in, "receipts": rs, "displayGroups": groups,
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
	if len(rs) == 100 {
		fmt.Fprintln(w, "    … older receipts not shown")
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

// writeInput — 원본을 받은 바이트 그대로 파일에 쓴다. 터미널에는 찍지 않는다(제어 문자가 그대로 나간다).
// 해시를 다시 재서 저장소가 준 바이트가 그 원본인지 확인한 뒤에 쓴다.
func writeInput(st store.Store, sha, out string, stderr io.Writer) error {
	raw, err := st.InputRaw(sha)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}
	if raw == nil {
		return fmt.Errorf("no input with sha256 %s in this organization", view.Safe(sha))
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != sha {
		return fmt.Errorf("stored input does not match its sha256 (got %s) — not written", got)
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
