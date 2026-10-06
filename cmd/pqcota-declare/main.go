// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-declare — 사용자 선언 인벤토리(CMDB/CSV)를 선언 레인 CollectionResult로 임포트한다(§2.3, SV-1).
// 관측이 아니라 선언(declared lane) — detection_method=UNSPECIFIED로 정직하게 표기(대조 기준선).
// 산출을 pqcota-ingest가 관측 결과와 동일 경로로 적재하도록 CollectionResult JSON을 출력 디렉터리에 쓴다.
//
//	입력 CSV: node_id,crypto_runtime,component
//
// usage: pqcota-declare [--out <dir>] <declaration.csv>
//
//	→ 이후: pqcota-ingest <dir>  (선언 레인이 히스토리에 적재됨)
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/declaration"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	out := flag.String("out", "declared-results", "directory to write the CollectionResult JSON into")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: pqcota-declare [--out <dir>] <declaration.csv>")
		os.Exit(2)
	}
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer f.Close()

	results, err := declaration.ImportCSV(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import:", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}

	for i, res := range results {
		b, err := protojson.Marshal(res)
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal:", err)
			os.Exit(1)
		}
		name := fmt.Sprintf("declared-%s-%d.json", safeName(res.GetEnvelope().GetTargetNodeId()), i)
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
	}

	fmt.Printf("%d declared-lane CollectionResults → %s/ (not observations; detection_method=UNSPECIFIED)\n", len(results), *out)
	fmt.Printf("next: pqcota-ingest %s  (with env PQCOTA_DSN it persists to Postgres)\n", *out)
}

// safeName — node_id를 파일명에 쓸 수 있게 다듬는다.
//
// node_id는 `cmdb://web-1`처럼 스킴을 달고 다니는 것이 이 리포의 규약인데, `/`가 그대로
// 들어가면 없는 하위 디렉터리를 가리켜 쓰기가 실패한다(실측: "no such file or directory").
// 파일명 자리에서만 바꾸고 Envelope의 target_node_id는 원본 그대로 둔다 — 식별자를 흔들면 적재
// 후 노드가 갈린다.
func safeName(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	// 스킴(`cmdb://`)이 `---`로 늘어지지 않게 연속 하이픈을 하나로.
	out := b.String()
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return strings.Trim(out, "-")
}
