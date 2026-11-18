// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-inventory — 중앙에서 실행. pqcota-ingest가 적재한 append-only 히스토리를 읽어
// 누적 인벤토리(발견 자산 + 관측 엣지 등급)를 조회한다. 읽기전용·무판단(§2.1).
// 파일 취합(discover-view, 휘발성)과 달리 영속 저장소에서 읽으므로 Postgres가 필요하다.
//
// 이력 열람·스냅샷 간 변화 diff는 관측 사실 서술이라 이 리포 범위 안이다(아키텍처 §6 기준).
// 선언(CMDB) 대조·리뷰확정 판정은 하지 않는다.
//
//	pqcota-inventory                       # 전 노드 최신 누적 뷰
//	pqcota-inventory -history node-db      # 그 노드의 스냅샷 이력(오래된 것부터)
//	pqcota-inventory -snapshot <id>        # 스냅샷 단건 상세(자산 + 관측 엣지)
//	pqcota-inventory -diff <과거id>,<최신id> # 두 스냅샷 사이의 변화(첫=과거·둘째=최신; 역순이면 경고)
//	pqcota-inventory -init-schema          # 인벤토리 단계의 표 전부를 만들고 끝난다(한 트랜잭션)
//
// env PQCOTA_DSN 필수 — pqcota-ingest와 같은 저장소.
//
// 조회는 DDL을 돌리지 않는다(v0.16.0부터). 표가 없으면 만들지 않고 -init-schema를 안내하며 멈춘다.
// v0.15.0까지는 조회도 적재와 같은 방식으로 저장소를 열어 빈 DB에 표를 만들었다 — 계약이 아니라 부수 효과였다.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/pgschema"
	sestore "github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/store"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	histNode := flag.String("history", "", "list a node's snapshot history (append-only measurement log)")
	snapID := flag.String("snapshot", "", "detail for one snapshot — assets and observed edges")
	diffPair := flag.String("diff", "", `changes between two snapshots — "older-id,newer-id" (first=older, second=newer; observations only, not a verdict)`)
	initSchema := flag.Bool("init-schema", false, "create every inventory table (history, metadata, source evidence) in one transaction and exit; run it as the schema owner, and again after each upgrade")
	flag.Parse()

	if *initSchema {
		if *histNode != "" || *snapID != "" || *diffPair != "" || flag.NArg() > 0 {
			fmt.Fprintln(os.Stderr, "-init-schema only creates the schema; it does not take -history, -snapshot, -diff or arguments")
			os.Exit(2)
		}
	}

	dsn := os.Getenv("PQCOTA_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "PQCOTA_DSN is required — it must point at the same Postgres that pqcota-ingest wrote to.")
		fmt.Fprintln(os.Stderr, "(the in-memory store is not shared across processes, so the query views assume a persistent store)")
		os.Exit(2)
	}
	if *initSchema {
		os.Exit(initialize(dsn))
	}
	// 조회는 DDL 없이 연다 — 빈 DB에 표를 만들지 않고, 읽기 권한만 있는 계정으로도 열린다.
	hist, err := history.OpenPgStoreIn(context.Background(), dsn, org.FromEnv())
	if err != nil {
		fmt.Fprintln(os.Stderr, "opening the history store:", err)
		os.Exit(1)
	}
	defer hist.Close()

	out, err := run(hist, dsn, *histNode, *snapID, *diffPair)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(out)
}

func run(store history.Store, dsn, histNode, snapID, diffPair string) (string, error) {
	switch {
	case histNode != "":
		snaps, err := store.Snapshots(histNode)
		if err != nil {
			return "", fmt.Errorf("reading history: %w", err)
		}
		stats, err := store.ObservationStats(histNode)
		if err != nil {
			return "", fmt.Errorf("reading observation stats: %w", err)
		}
		// 절단 기록은 있으면 곁들인다 — 조회 도구는 Pruner를 요구하지 않는다(파괴적 동작과 분리).
		var pruned []history.RetentionEvent
		if pr, ok := store.(history.Pruner); ok {
			if pruned, err = pr.RetentionEvents(histNode); err != nil {
				return "", fmt.Errorf("reading retention events: %w", err)
			}
		}
		// 지금 상태는 맨 아래 행이 아닐 수 있다(같은 내용이 돌아오면 옛 스냅샷을 다시 쓴다) — 따로 표시한다.
		current := ""
		if cur, err := store.Latest(histNode); err != nil {
			return "", fmt.Errorf("reading the current snapshot: %w", err)
		} else if cur != nil {
			current = cur.ID
		}
		return inventory.RenderHistoryWithCurrent(histNode, snaps, stats, pruned, current), nil

	case snapID != "":
		snap, err := mustSnapshot(store, snapID)
		if err != nil {
			return "", err
		}
		// 사람이 선언한 앱을 **읽을 때만** 얹는다 — 저장된 관측 엣지는 그대로다.
		return inventory.RenderDetailWith(snap, declaredOverlay(store)), nil

	case diffPair != "":
		ids := strings.Split(diffPair, ",")
		if len(ids) != 2 || strings.TrimSpace(ids[0]) == "" || strings.TrimSpace(ids[1]) == "" {
			return "", fmt.Errorf(`-diff takes "id1,id2" (got %q)`, diffPair)
		}
		a, err := mustSnapshot(store, strings.TrimSpace(ids[0]))
		if err != nil {
			return "", err
		}
		b, err := mustSnapshot(store, strings.TrimSpace(ids[1]))
		if err != nil {
			return "", err
		}
		if a.NodeID != b.NodeID {
			return "", fmt.Errorf("snapshots from different nodes are not compared (%s vs %s)", a.NodeID, b.NodeID)
		}
		return inventory.RenderDiff(a, b), nil
	}

	// 기본 — 전 노드 최신 누적 뷰. 머신 메타데이터(엔드포인트·프로필)를 헤더에 곁들인다(인벤토리 설계 §2.0).
	meta, err := inventory.OpenPgMetaStoreIn(context.Background(), dsn, org.FromEnv())
	if err != nil {
		return "", fmt.Errorf("metadata store: %w", err)
	}
	defer meta.Close()
	out, err := inventory.RenderStore(store, meta)
	if err != nil {
		return "", fmt.Errorf("render: %w", err)
	}
	return out, nil
}

// declaredOverlay — 선언 저장소에서 색인을 만든다. 담지 못하는 저장소면 빈 색인이다.
func declaredOverlay(store history.Store) *inventory.AttributionOverlay {
	as, _ := store.(history.AttributionStore)
	return inventory.BuildAttributionOverlay(as)
}

func mustSnapshot(store history.Store, id string) (*history.Snapshot, error) {
	s, err := store.ByID(id)
	if err != nil {
		return nil, fmt.Errorf("reading snapshot (%s): %w", id, err)
	}
	if s == nil {
		return nil, fmt.Errorf("no such snapshot: %s", id)
	}
	return s, nil
}

// initialize — -init-schema. 성공 줄은 커밋하고 표·열을 다시 확인한 뒤에만 낸다.
func initialize(dsn string) int {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connecting to Postgres:", err)
		return 1
	}
	defer pool.Close()
	rep, err := pgschema.Init(ctx, pool, history.Schema(), inventory.MetaSchema(), sestore.Schema())
	if err != nil {
		fmt.Fprintln(os.Stderr, "initializing the schema failed:", err)
		if pgschema.IsPrivilegeError(err) {
			fmt.Fprintln(os.Stderr, "(this account may not own the existing pqcota tables, or lacks USAGE/CREATE on the schema. "+
				"Run -init-schema as the role that owns them, or move their ownership to the schema role first: "+
				"https://github.com/randyinthedev-hash/pqcota-inventory/blob/main/cmd/README.md#setting-up-the-database)")
		}
		return 1
	}
	fmt.Print(pgschema.FormatReport(rep))
	return 0
}
