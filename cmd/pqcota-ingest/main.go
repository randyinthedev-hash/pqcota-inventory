// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-ingest — 중앙(인벤토리 호스트)에서 실행. 엣지 노드들이 낸 CollectionResult
// JSON들을 취합해 스코프 게이트 → 정규화 → append-only 히스토리에 적재한다(§1.4·§2.4⑥).
// 엣지↔중앙 경계를 넘어온 정규화된 계약을 실제로 "적재"하는 관문 — 데모의 휘발성 뷰를
// 누적 중앙 인벤토리로 승격시킨다.
//
// usage: pqcota-ingest [-scope-assets <csv>] <results-dir> [scope-master-file]
//
//	results-dir       : *.json(단일 객체)·*.jsonl(한 줄=한 결과) — Ansible/업로드로 회수된 것.
//	                    형식은 확장자가 아니라 내용으로 판별한다(pkg/inventory/resultio).
//	                    **해독하지 못한 입력이 하나라도 있으면 적재하지 않는다** — 반쪽짜리
//	                    적재는 빠진 자산과 없는 자산을 구별할 수 없게 만든다(§2.6).
//	scope-master-file : (선택) 등재 노드 ID 목록(한 줄에 하나). 없으면 게이트 생략(로컬/데모).
//	-scope-assets     : (선택) 자산 스코프 정책 CSV. 노드는 등재됐어도 그 안에서 **계속 관리할
//	                    자산만** 남긴다(§1.4 노드 게이트를 자산 단위로). 제외분은 적재되지 않되
//	                    몇 건인지 고지된다 — 제외는 부재가 아니다(§2.6).
//	env PQCOTA_DSN     : (선택) 있으면 Postgres 영속화, 없으면 인메모리(요약만).
//	env PQCOTA_VERIFY_KEY        : (선택) 콤마 구분 base64 공개키. 있으면 서명 검증.
//	env PQCOTA_REQUIRE_SIGNATURE : "1"이면 검증할 키가 없을 때 **적재를 시작하지 않는다.**
//	                               알리지 않고 통과하는 경로를 닫아야 하는 배포용(§2.6).
//	env PQCOTA_ORG               : (선택) 이 적재가 속할 조직. 여러 조직이 한 저장소를 쓰면 필수.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/scope"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/ingest"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/resultio"
)

func main() {
	scopeAssets := flag.String("scope-assets", "",
		"asset scope policy CSV — what stays managed within a node (action,runtime,lib,app_key,note)")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: pqcota-ingest [-scope-assets <csv>] <results-dir> [scope-master-file]")
		os.Exit(2)
	}
	dir := args[0]

	var master *scope.Master
	if len(args) > 1 {
		ids, err := readScope(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "reading scope:", err)
			os.Exit(1)
		}
		master = scope.NewMaster(ids)
	}

	results, flaws := resultio.LoadDir(dir)
	// **해독하지 못한 입력에서 멈춘다.** 예전에는 알리지 않고 건너뛰었는데, 그러면 그 파일에 있던
	// 자산이 화면에서 "처음부터 없던 것"과 똑같이 보인다 — 성공처럼 보이는 실패다(§2.6).
	// 판단은 여기서 한다: 디코더는 읽은 것과 못 읽은 것을 함께 돌려주고, 관문인 이쪽이 막는다.
	for _, f := range flaws {
		fmt.Fprintln(os.Stderr, "could not decode:", f)
	}
	if len(flaws) > 0 {
		fmt.Fprintf(os.Stderr, "%d input(s) could not be decoded — refusing to ingest a partial set. Fix or remove them, then run again.\n", len(flaws))
		os.Exit(1)
	}
	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "no result found: %s/*.json or %s/*.jsonl\n", dir, dir)
		os.Exit(1)
	}

	store, closeFn, persistent := openStore()
	defer closeFn()

	// 서명 검증(§2.6) — PQCOTA_VERIFY_KEY(콤마 구분 base64 공개키)가 있으면. 없으면 생략.
	var verifySig func(*discoveryv1.CollectionResult) bool
	if pubs := envKeys("PQCOTA_VERIFY_KEY"); len(pubs) > 0 {
		verifySig = func(r *discoveryv1.CollectionResult) bool { return sign.Verify(pubs, r) }
	}

	// 밀리초까지 — 스냅샷 id(prefix+":"+node)는 -snapshot·-diff가 쓰는 사용자 손잡이라
	// 유일해야 한다. 초 단위면 같은 초에 두 번 적재할 때 id가 충돌한다.
	prefix := "ingest-" + time.Now().UTC().Format("20060102T150405.000Z")
	// 자산 스코프 — 노드는 등재됐어도 그 안의 자산 중 관리 대상만 남긴다(§1.4를 자산 단위로).
	assetPolicy, err := loadAssetPolicy(*scopeAssets)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	opts := ingest.IngestOptions{
		Master: master, VerifySig: verifySig, SnapshotPrefix: prefix,
		RulesetVersion: normalize.RulesetVersion, Store: store, AssetPolicy: assetPolicy,
		RequireSignature: os.Getenv("PQCOTA_REQUIRE_SIGNATURE") == "1",
	}
	// 거절 기록은 남길 수 있을 때만 남긴다 — 인메모리 저장소도 같은 규칙을 만족하므로
	// 데모에서도 같은 경로를 탄다(실제에 없는 경로를 타지 않게).
	if rs, ok := store.(ingest.RejectionStore); ok {
		opts.Rejections = rs
	}
	rep, err := ingest.IngestWith(results, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ingest:", err)
		os.Exit(1)
	}

	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║  pqcota central ingest (discovery → history)      ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	backing := "in-memory (summary only — gone when the process exits)"
	if persistent {
		backing = "Postgres (append-only, persistent)"
	}
	fmt.Printf("input: %d CollectionResults · store: %s\n", len(results), backing)
	if master != nil {
		fmt.Printf("scope gate: only registered nodes are ingested (the rest become registration requests)\n")
	} else {
		fmt.Printf("scope gate: skipped (no CMDB given)\n")
	}
	if verifySig != nil {
		fmt.Printf("signature check: verified with PQCOTA_VERIFY_KEY (mismatches are rejected, §2.6)\n")
	} else {
		fmt.Printf("signature check: **not done** — no public key to verify with. The assumption is that transport security covers it.\n")
		fmt.Printf("           where that assumption does not hold, block it with PQCOTA_REQUIRE_SIGNATURE=1.\n")
	}
	// 스냅샷은 실질 내용이 바뀐 노드에만 새로 생긴다 — 나머지는 관측 기록만 남아
	// "봤다"는 사실은 보존하되 같은 상태를 중복 저장하지 않는다.
	fmt.Printf("\ningest result: accepted %d · unregistered/no-anchor %d · signature-rejected %d → %d nodes observed (changed %d · identical %d)\n",
		rep.Accepted, rep.OffScope, rep.Rejected, rep.Snapshots, rep.Changed, rep.Snapshots-rep.Changed)
	if rep.Unverified > 0 {
		// 확인하지 못한 것을 통과와 같은 자리에 두지 않는다 — 서명거부와도 다르다(§2.6).
		fmt.Printf("unverified signatures: %d — this does not mean they are wrong, it means **they were never checked**.\n", rep.Unverified)
	}
	if rep.ExcludedByScope > 0 {
		// 제외는 "없음"이 아니다 — 몇 건을 왜 뺐는지 반드시 밝힌다(§2.6).
		fmt.Printf("asset scope: %d excluded as out of scope (observed, but not ingested)\n", rep.ExcludedByScope)
	}

	for _, node := range rep.Nodes {
		snap, _ := store.Latest(node)
		if snap == nil {
			continue
		}
		fmt.Printf("  • %-12s assets %d · observed edges %d\n", node, len(snap.Findings), len(snap.Edges))
	}
	for _, n := range rep.Notes {
		fmt.Printf("  ⚠ %s\n", n)
	}
	for _, c := range rep.Conflicts {
		if c.Kind == "duplicate" {
			fmt.Printf("  ⚠ duplicate: physical machine %s registered under several node_ids → %v (same machine, different names)\n", c.Key, c.Members)
		} else {
			fmt.Printf("  ⚠ collision: node_id %s points at several machines → %v (suspect a re-image or a mislabel)\n", c.Key, c.Members)
		}
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

// envKeys — 환경변수의 콤마 구분 base64 공개키 목록.
func envKeys(name string) []string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return nil
	}
	var out []string
	for _, k := range strings.Split(v, ",") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func readScope(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids = append(ids, line)
	}
	return ids, sc.Err()
}

// loadAssetPolicy — 자산 스코프 정책 CSV를 읽는다. 경로가 비면 nil(전부 관리 대상).
func loadAssetPolicy(path string) (*scope.AssetPolicy, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening the asset scope: %w", err)
	}
	defer f.Close()
	return scope.LoadAssetPolicy(f)
}
