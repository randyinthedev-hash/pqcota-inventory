// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-cbom-ingest — 외부(CBOMkit 등) CycloneDX CBOM을 수신·검증·적재한다(SV-2·SD-7).
// 위임 수신(② 위임)의 종단 진입점: 소스·아티팩트를 pqcota가 스캔하지 않고, 사용자 CI가 낸
// 표준 CycloneDX를 받아 관측 레인(detection_method=source/artifact)으로 히스토리에 적재한다.
//
// 검증은 이 커맨드 안에서 강제된다(ImportCBOM 내부): (1) 서명(옵션) → (2) 구조 → (3) 앵커.
// 부적합 CBOM은 저장되지 않으므로 별도 프리플라이트 커맨드가 필요 없다.
//
// usage: pqcota-cbom-ingest <cbom.json | -> <target-node-id>
//
//	<cbom.json | ->   : CycloneDX CBOM 파일(또는 stdin '-')
//	<target-node-id>  : 이 CBOM을 달아 둘 스코프 노드 ID(§1.4 앵커). 없으면 스코프 판정 요청(SD-5).
//	env PQCOTA_DSN     : (선택) 있으면 Postgres 영속화, 없으면 인메모리(요약만).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/ingest"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: pqcota-cbom-ingest <cbom.json | -> <target-node-id>")
		os.Exit(2)
	}
	src, nodeID := os.Args[1], os.Args[2]

	var raw []byte
	var err error
	if src == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(src)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}

	store, closeFn, persistent := openStore()
	defer closeFn()

	// CBOM 서명 검증(verifySig)은 아직 미배선 — CBOM은 신뢰된 CI/전송 경로로 온다는 전제(SV-2).
	// sign 패키지는 CollectionResult의 정규화 바이트에 서명하는데 여기 오는 것은 사용자 CI가 낸
	// 원본 CycloneDX라, 무엇을 서명으로 볼지부터 정해야 한다(검토 중인 설계 §10).
	//
	// **검증하지 않았다는 사실을 알린다.** 아무 말도 하지 않으면 검증한 것과 구별되지 않는다
	// (§2.6 갭 ≠ 부재). pqcota-ingest가 키 없이 돌 때 내는 줄과 같은 자리다.
	fmt.Fprintln(os.Stderr, "signature check: **not done** — this entrance has no key to verify with, so the CBOM's authenticity rests on your CI and transport (SV-2).")
	prefix := "cbom-" + time.Now().UTC().Format("20060102T150405Z")
	disp, err := ingest.IngestCBOM(raw, nodeID, nil, prefix, normalize.RulesetVersion, store)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ingest:", err)
		os.Exit(1)
	}

	backing := "in-memory (summary only — gone when the process exits)"
	if persistent {
		backing = "Postgres (append-only, persistent)"
	}
	switch disp {
	case ingest.Accepted:
		n := 0
		if snap, _ := store.Latest(nodeID); snap != nil {
			n = len(snap.Findings)
		}
		fmt.Println("╔══════════════════════════════════════════════════╗")
		fmt.Println("║  pqcota CBOM intake (delegated → observed lane → history) ║")
		fmt.Println("╚══════════════════════════════════════════════════╝")
		fmt.Printf("✓ accepted: node=%s · detection_method=source/artifact · %d assets · store %s\n", nodeID, n, backing)
	case ingest.NeedsScopeBinding:
		fmt.Fprintf(os.Stderr, "✗ no anchor: <target-node-id> must exist in the scope master (§1.4, SD-5)\n")
		os.Exit(1)
	default: // Rejected
		fmt.Fprintf(os.Stderr, "✗ rejected: CBOM validation failed (signature, structure or spec version, TV-CBOM-1)\n")
		os.Exit(1)
	}
}

func openStore() (history.Store, func(), bool) {
	dsn := os.Getenv("PQCOTA_DSN")
	if dsn == "" {
		mem, err := history.NewMemStoreIn(org.FromEnv())
		if err != nil {
			fmt.Fprintln(os.Stderr, "organization:", err)
			os.Exit(2)
		}
		return mem, func() {}, false
	}
	pg, err := history.NewPgStoreIn(context.Background(), dsn, org.FromEnv())
	if err != nil {
		// **인메모리로 대체하지 않는다.** v0.1.x는 여기서 폴백했는데, 그러면 적재된 줄 알았던
		// 것이 프로세스와 함께 사라지고 화면에는 성공이 찍힌다 — 성공처럼 보이는 실패다.
		// DSN을 준 것은 영속을 요구한 것이고, 그 요구를 못 들어주면 멈추는 것이 맞다.
		fmt.Fprintln(os.Stderr, "could not open the store:", err)
		os.Exit(1)
	}
	return pg, pg.Close, true
}
