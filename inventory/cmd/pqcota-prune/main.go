// Command pqcota-prune — 보존 정책 집행(오래된 변화 지점 절단).
//
// **조회 커맨드(pqcota-inventory)와 일부러 분리했다** — 읽기 도구가 파괴적 동작을 겸하면
// 실수 한 번이 이력을 지운다.
//
// 기본은 dry-run이다. 무엇을 얼마나 지울지 먼저 보이고, 실제 삭제는 -apply로만 한다.
//
//	pqcota-prune -keep-last 20                  # 계획만(아무것도 안 지움)
//	pqcota-prune -older-than 90d -apply         # 실제 절단
//	pqcota-prune -older-than 90d -keep-last 20  # 둘 다: 보수적 판정(둘 다 버려도 될 때만)
//
// 불변식: 노드별 **최신 스냅샷은 어떤 정책으로도 지우지 않는다**(인벤토리 뷰·프로비저닝
// before 캡처의 근거). 절단하면 그 사실이 기록으로 남아 이력의 구멍을 설명한다.
//
// env PQCOTA_DSN 필수.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

func main() {
	olderThan := flag.String("older-than", "", "prune change points older than this (e.g. 90d, 720h)")
	keepLast := flag.Int("keep-last", 0, "keep the newest N change points per node")
	apply := flag.Bool("apply", false, "actually delete (default is plan only)")
	flag.Parse()

	dur, err := parseDuration(*olderThan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	pol := history.Policy{OlderThan: dur, KeepLast: *keepLast}

	dsn := os.Getenv("PQCOTA_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "PQCOTA_DSN is required — it must point at the persistent store to prune.")
		os.Exit(2)
	}
	store, err := history.NewPgStoreIn(context.Background(), dsn, org.FromEnv())
	if err != nil {
		fmt.Fprintln(os.Stderr, "connecting to Postgres:", err)
		os.Exit(1)
	}
	defer store.Close()

	rep, err := store.Prune(pol, *apply)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(render(rep))
}

func render(rep *history.PruneReport) string {
	var b strings.Builder
	mode := "plan (dry run — nothing was deleted)"
	if rep.Applied {
		mode = "applied"
	}
	fmt.Fprintf(&b, "retention policy %s — %s\n\n", rep.Policy.String(), mode)
	if len(rep.Nodes) == 0 {
		b.WriteString("nothing to prune. (the newest snapshot per node is kept under every policy)\n")
		return b.String()
	}
	fmt.Fprintf(&b, "%-24s %10s %10s  %s\n", "node", "snapshots", "observed", "through")
	for _, n := range rep.Nodes {
		fmt.Fprintf(&b, "%-24s %10d %10d  %s\n",
			n.NodeID, n.Snapshots, n.Observations, n.UpTo.Format("2006-01-02 15:04:05"))
	}
	s, o := rep.Total()
	fmt.Fprintf(&b, "\ntotals: %s · %s\n", inventory.Plural(s, "change point"), inventory.Plural(o, "observation"))
	if !rep.Applied {
		b.WriteString("add -apply to actually delete. The pruning itself is recorded and reported in the history.\n")
	}
	return b.String()
}

// parseDuration — time.ParseDuration에 일(day) 단위를 더한다("90d"). 보존 정책은 일 단위로
// 말하는 게 자연스러운데 표준 파서는 시간까지만 안다.
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid -older-than: %q (e.g. 90d, 720h)", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid -older-than: %q (e.g. 90d, 720h)", s)
	}
	return d, nil
}
