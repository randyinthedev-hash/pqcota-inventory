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
	"strings"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/store"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/view"
)

// maxSourceEvidenceInput — 읽기 전부터 거는 원문 상한(설계 §6의 검토 시작값 32 MiB, 확정값 아님).
const maxSourceEvidenceInput = 32 << 20

// OutputFormat — `--json` 출력의 판(계약 검토 §6.1). 같은 판에서는 필드를 더하기만 한다.
const OutputFormat = "pqcota-source-evidence/v1"

type seOpts struct {
	dryRun         bool
	json           bool
	input          string
	node           string
	preset         string // 내장 프리셋 id
	sourceMap      string // 사용자 매핑 설정 파일
	allowUnmatched bool   // 한 번도 맞지 않은 규칙이 있어도 위치 없이 계속한다(사용자가 밝힌 경우만)
}

const seUsage = "usage: pqcota-cbom-ingest <cbom.json | -> [target-node-id] --source-evidence [--preset <id>] [--source-map <file>] [--allow-unmatched-rules] [--dry-run] [--json]"

// parseSourceEvidence — 옵션(`-`로 시작하고 `-` 하나가 아닌 인자)이 하나도 없으면 handled=false(기존 경로).
// 옵션이 하나라도 있으면 여기서 처리하고, 모르는 옵션은 종료 코드 2로 멈춘다 — 기존 경로는 옵션을 모르고
// 남는 인자를 버리므로, 철자가 틀린 플래그나 아직 없는 `--source-map`을 넘기면 스냅샷을 써 버린다.
// 플래그는 위치 인자 앞뒤 어디에 와도 된다(설계 §5.4의 예가 뒤에 붙인다).
func parseSourceEvidence(args []string) (o seOpts, handled bool, err error) {
	var se bool
	var pos, unknown, problems []string
	// value — `--name value`와 `--name=value`. 값이 없거나 두 번 주면 문제로 모은다.
	value := func(name string, i *int, a string, dst *string) {
		handled = true
		v, inline := "", false
		if strings.HasPrefix(a, name+"=") {
			v, inline = strings.TrimPrefix(a, name+"="), true
		}
		if !inline {
			if *i+1 >= len(args) {
				problems = append(problems, name+" needs a value")
				return
			}
			*i++
			v = args[*i]
		}
		switch {
		case v == "" || strings.HasPrefix(v, "-"):
			problems = append(problems, fmt.Sprintf("%s needs a value, got %q", name, v))
		case *dst != "":
			problems = append(problems, name+" is given twice")
		default:
			*dst = v
		}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--source-evidence":
			se, handled = true, true
		case a == "--dry-run":
			o.dryRun, handled = true, true
		case a == "--json":
			o.json, handled = true, true
		case a == "--allow-unmatched-rules":
			o.allowUnmatched, handled = true, true
		case a == "--preset" || strings.HasPrefix(a, "--preset="):
			value("--preset", &i, a, &o.preset)
		case a == "--source-map" || strings.HasPrefix(a, "--source-map="):
			value("--source-map", &i, a, &o.sourceMap)
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				unknown = append(unknown, a)
				handled = true
				continue
			}
			pos = append(pos, a)
		}
	}
	if !handled {
		return o, false, nil
	}
	if len(unknown) > 0 {
		return o, true, fmt.Errorf("unknown option %s — nothing was written", strings.Join(unknown, " "))
	}
	if len(problems) > 0 {
		return o, true, fmt.Errorf("%s — nothing was written", strings.Join(problems, "; "))
	}
	// --dry-run만 주고 --source-evidence를 빠뜨리면 기존 경로가 스냅샷을 쓴다. 미리보기인 줄 알고
	// 적재하는 일을 막으려고 멈춘다.
	if !se {
		return o, true, errors.New("these options only work with --source-evidence; without it this command writes a runtime snapshot — nothing was written")
	}
	switch len(pos) {
	case 1:
		o.input = pos[0]
	case 2:
		o.input, o.node = pos[0], pos[1]
	default:
		return o, true, errors.New(seUsage)
	}
	return o, true, nil
}

// storeKind — 어디에 저장했나. 인메모리는 프로세스와 함께 사라지므로 자동화가 구분할 수 있게 JSON에 낸다.
type storeKind string

const (
	storeMemory   storeKind = "memory"
	storePostgres storeKind = "postgres"
)

func (k storeKind) persistent() bool { return k == storePostgres }

func (k storeKind) label() string {
	if k == storePostgres {
		return "Postgres (persistent)"
	}
	return "in-memory (gone when the process exits)"
}

// seStoreOpener — 저장소를 여는 자리. 시험이 바꿔 끼운다.
type seStoreOpener func() (st store.Store, closeFn func(), kind storeKind, err error)

func openSourceEvidenceStore() (store.Store, func(), storeKind, error) {
	dsn := os.Getenv("PQCOTA_DSN")
	if dsn == "" {
		m, err := store.NewMemStoreIn(org.FromEnv())
		return m, func() {}, storeMemory, err
	}
	// 기존 경로와 같이 인메모리로 대체하지 않는다 — 영속을 요구했는데 못 들어주면 멈춘다.
	p, err := store.NewPgStoreIn(context.Background(), dsn, org.FromEnv())
	if err != nil {
		return nil, nil, "", err
	}
	return p, p.Close, storePostgres, nil
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
	Kind           string                         `json:"kind"` // "ingest". 조회(pqcota-source-evidence)와 같은 판을 쓰고 이것으로 가른다
	DryRun         bool                           `json:"dryRun"`
	TargetNode     string                         `json:"targetNode"`
	Stored         bool                           `json:"stored"`
	StoreKind      storeKind                      `json:"storeKind"`  // "memory"·"postgres", 저장하지 않았으면 ""
	Persistent     bool                           `json:"persistent"` // 프로세스가 끝난 뒤에도 남는가
	Receipt        *store.Receipt                 `json:"receipt"`
	Refused        bool                           `json:"refused"`  // 매핑 오류로 저장하지 않았다(미리보기면 저장하지 않을 것이다)
	Refusals       []sourceevidence.Diagnostic    `json:"refusals"` // 그 이유. 없으면 빈 목록
	Interpretation *sourceevidence.Interpretation `json:"interpretation"`
}

// loadMaps — 프리셋, 사용자 설정 순서. 설정이 잘못됐으면 변환하지 않는다(설계 §5.4).
func loadMaps(o seOpts) ([]*sourceevidence.LoadedMap, error) {
	var out []*sourceevidence.LoadedMap
	if o.preset != "" {
		lm, err := sourceevidence.LoadPreset(o.preset)
		if err != nil {
			var ids []string
			for _, p := range sourceevidence.Presets() {
				ids = append(ids, p.ID)
			}
			return nil, fmt.Errorf("%w (presets: %s)", err, strings.Join(ids, ", "))
		}
		out = append(out, lm)
	}
	if o.sourceMap != "" {
		f, err := os.Open(o.sourceMap)
		if err != nil {
			return nil, err
		}
		raw, err := readLimited(f, sourceevidence.MaxMapBytes)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("source map: %w", err)
		}
		lm, err := sourceevidence.LoadMap(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, lm)
	}
	return out, nil
}

// runSourceEvidence — 종료 코드를 돌려준다. 저장에 실패하면 성공을 찍지 않는다(설계 §6).
func runSourceEvidence(o seOpts, stdin io.Reader, stdout, stderr io.Writer, open seStoreOpener) int {
	raw, err := readSourceEvidenceInput(o.input, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "read:", err)
		return 1
	}
	maps, err := loadMaps(o)
	if err != nil {
		fmt.Fprintln(stderr, "✗ mapping not usable, nothing was written:", err)
		return 2
	}
	interp, err := sourceevidence.ConvertWith(raw, sourceevidence.DefaultLimits, maps)
	if err != nil {
		fmt.Fprintln(stderr, "✗ not converted, nothing was written:", err)
		return 1
	}
	refusals := sourceevidence.Refusals(interp, o.allowUnmatched)
	if refusals == nil {
		refusals = []sourceevidence.Diagnostic{}
	}

	var rc *store.Receipt
	var backing storeKind
	if !o.dryRun && len(refusals) == 0 {
		// 미리보기는 저장소를 열지도 않는다 — 스키마 자동 생성도 DB 쓰기다.
		st, closeFn, b, err := open()
		if err != nil {
			fmt.Fprintln(stderr, "could not open the source evidence store:", err)
			return 1
		}
		defer closeFn()
		r, err := st.Save(store.Input{NodeID: o.node, Raw: raw, Maps: store.MapsOf(maps)}, interp)
		if err != nil {
			fmt.Fprintln(stderr, "✗ not stored:", err)
			return 1
		}
		rc, backing = &r, b
	}

	if o.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(seJSON{Format: OutputFormat, Kind: "ingest", DryRun: o.dryRun, TargetNode: o.node,
			Stored: rc != nil, StoreKind: backing, Persistent: backing.persistent(), Receipt: rc,
			Refused: len(refusals) > 0, Refusals: refusals, Interpretation: interp}); err != nil {
			fmt.Fprintln(stderr, "write:", err)
			return 1
		}
		if len(refusals) > 0 {
			fmt.Fprintf(stderr, "✗ not stored: %d mapping problems\n", len(refusals))
			return 1
		}
		return 0
	}
	fmt.Fprint(stdout, "source evidence — locations the CBOM reported, for review. No runtime snapshot is created.\n\n")
	if o.node != "" {
		fmt.Fprintf(stdout, "target node     %s (user-specified; not checked against the scope master)\n", view.Safe(o.node))
	} else {
		fmt.Fprint(stdout, "target node     not given\n")
	}
	view.Interpretation(stdout, interp, int64(len(raw)))
	if len(refusals) > 0 {
		verb := "✗ not stored"
		if o.dryRun {
			verb = "✗ dry run: this would not be stored"
		}
		fmt.Fprintf(stdout, "\n%s — %d mapping problems (a mapping you named must convert without errors):\n", verb, len(refusals))
		for _, d := range refusals {
			fmt.Fprintf(stdout, "    %s %s %s\n", d.Code, view.Safe(d.Pointer), view.Safe(d.Detail))
		}
		for _, d := range refusals {
			if d.Code == sourceevidence.DiagMapRuleUnmatched {
				fmt.Fprintln(stdout, "  a rule that matched nothing may be a mistake in the mapping; --allow-unmatched-rules continues without its locations.")
				break
			}
		}
		return 1
	}
	if rc == nil {
		fmt.Fprintln(stdout, "\ndry run: nothing was written.")
		return 0
	}
	fmt.Fprintf(stdout, "\n✓ stored in %s: receipt #%d · new input: %s · new interpretation: %s\n",
		backing.label(), rc.Seq, yesNo(rc.NewInput), yesNo(rc.NewInterpretation))
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
