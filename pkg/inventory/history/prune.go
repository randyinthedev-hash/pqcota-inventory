package history

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// 보존 정책(절단, 인벤토리 설계 §7.4) — 관측 기록 분리(§7.2)로 같은 상태의 반복은 이미 접히므로, 여기서 다루는 것은
// **오래된 변화 지점**뿐이다. 저장된 스냅샷은 전부 변화 지점이라 "변화점 보존" 축은 필요 없다.
//
// 원칙 셋:
//   - **수정 금지.** 남은 스냅샷은 바이트 그대로다. 절단은 과거를 바꾸는 게 아니라 보관을 끝내는 것이라
//     append-only 불변식(§1.2)과 양립한다.
//   - **최신 불가침.** 노드별 최신 스냅샷은 어떤 정책으로도 지우지 않는다 — 인벤토리 뷰와
//     프로비저닝 before 캡처의 근거다.
//   - **지운 사실을 남긴다.** 절단하면 이력에 구멍이 생기는데, 기록이 없으면 "관측을 안 한 것"과
//     구분되지 않는다. §2.6 "갭 ≠ 부재"를 시간축으로 옮긴 것이다.

// Policy — 보존 정책. 0값은 "그 축 미적용".
//
// 두 축을 다 주면 **보수적으로** 판정한다 — 둘 다 "버려도 된다"고 할 때만 지운다
// (최근 N개 안에 들거나 아직 안 오래됐으면 보존). 파괴적 동작이라 의심스러우면 남긴다.
type Policy struct {
	OlderThan time.Duration // 이보다 오래된 변화 지점을 절단 대상으로
	KeepLast  int           // 노드별 최근 N개 변화 지점은 보존
}

// ErrNoPolicy — 축을 하나도 안 주면 "최신만 남기고 전부 삭제"가 되어 위험하므로 거부한다.
var ErrNoPolicy = errors.New("at least one retention policy must be given (older-than or keep-last)")

func (p Policy) validate() error {
	if p.OlderThan <= 0 && p.KeepLast <= 0 {
		return ErrNoPolicy
	}
	return nil
}

func (p Policy) String() string {
	var parts []string
	if p.OlderThan > 0 {
		parts = append(parts, "older-than="+humanDuration(p.OlderThan))
	}
	if p.KeepLast > 0 {
		parts = append(parts, fmt.Sprintf("keep-last=%d", p.KeepLast))
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return parts[0] + func() string {
		if len(parts) > 1 {
			return " " + parts[1]
		}
		return ""
	}()
}

// humanDuration — 일 단위로 떨어지면 "90d"로 쓴다. 이 문자열은 절단 기록에 **영구히 남으므로**
// 사용자가 입력한 형태(90d)와 어긋나지 않아야 나중에 "무슨 정책이었나"를 읽을 수 있다.
func humanDuration(d time.Duration) string {
	const day = 24 * time.Hour
	if d >= day && d%day == 0 {
		return fmt.Sprintf("%dd", d/day)
	}
	return d.String()
}

// NodePrune — 한 노드에서 절단될(또는 절단된) 분량.
type NodePrune struct {
	NodeID       string
	Snapshots    int
	Observations int
	UpTo         time.Time // 이 시각 이전을 잘랐다
}

// PruneReport — 절단 계획(dry-run) 또는 결과.
type PruneReport struct {
	Applied bool // false면 계획만 세운 것(아무것도 지우지 않음)
	Policy  Policy
	Nodes   []NodePrune
}

func (r *PruneReport) Total() (snaps, obs int) {
	for _, n := range r.Nodes {
		snaps += n.Snapshots
		obs += n.Observations
	}
	return
}

// RetentionEvent — 절단이 실제로 일어났다는 기록. 이력 뷰가 구멍을 설명하는 근거.
type RetentionEvent struct {
	NodeID       string
	PrunedUpTo   time.Time
	Snapshots    int
	Observations int
	Policy       string
	ExecutedAt   time.Time
}

// Pruner — 보존 정책 집행. **조회용 Store와 분리한다** — 읽기 도구가 파괴적 동작을 겸하면
// 실수 한 번이 이력을 지운다. 영속 저장소가 구현한다(인메모리는 프로세스와 함께 사라지므로
// 테스트 목적으로만).
type Pruner interface {
	Prune(p Policy, apply bool) (*PruneReport, error)
	RetentionEvents(nodeID string) ([]RetentionEvent, error)
}

// prunable — 정책에 따라 지울 스냅샷을 고른다. snaps는 seq 오름차순(오래된 것부터).
// 최신 1건은 무조건 보존한다.
func prunable(snaps []*Snapshot, p Policy, now time.Time) []*Snapshot {
	if len(snaps) <= 1 {
		return nil // 최신 불가침 — 1건뿐이면 지울 게 없다
	}
	cutoff := now
	if p.OlderThan > 0 {
		cutoff = now.Add(-p.OlderThan)
	}
	var out []*Snapshot
	for i, s := range snaps {
		if i == len(snaps)-1 {
			break // 최신 불가침
		}
		rn := len(snaps) - i // 최신이 1
		if p.KeepLast > 0 && rn <= p.KeepLast {
			continue // 최근 N개 안 — 보존
		}
		if p.OlderThan > 0 && !s.CreatedAt.Before(cutoff) {
			continue // 아직 안 오래됨 — 보존
		}
		out = append(out, s)
	}
	return out
}

// Prune — MemStore 구현(테스트용). 영속 저장소와 같은 판정 규칙을 쓴다.
func (m *MemStore) Prune(p Policy, apply bool) (*PruneReport, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	rep := &PruneReport{Applied: apply, Policy: p}

	nodes := make([]string, 0, len(m.byNode))
	for n := range m.byNode {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)

	for _, node := range nodes {
		victims := prunable(m.byNode[node], p, now)
		if len(victims) == 0 {
			continue
		}
		np := NodePrune{NodeID: node, Snapshots: len(victims), UpTo: victims[len(victims)-1].CreatedAt}
		dead := map[string]bool{}
		for _, v := range victims {
			dead[v.ID] = true
			np.Observations += m.obs[node][v.ID].count()
		}
		if apply {
			var kept []*Snapshot
			for _, s := range m.byNode[node] {
				if !dead[s.ID] {
					kept = append(kept, s)
					continue
				}
				delete(m.hash, s.ID)
				delete(m.obs[node], s.ID)
			}
			m.byNode[node] = kept
			m.events = append(m.events, RetentionEvent{
				NodeID: node, PrunedUpTo: np.UpTo, Snapshots: np.Snapshots,
				Observations: np.Observations, Policy: p.String(), ExecutedAt: now,
			})
		}
		rep.Nodes = append(rep.Nodes, np)
	}
	return rep, nil
}

func (m *MemStore) RetentionEvents(nodeID string) ([]RetentionEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []RetentionEvent
	for _, e := range m.events {
		if e.NodeID == nodeID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *ObsStat) count() int {
	if s == nil {
		return 0
	}
	return s.Count
}
