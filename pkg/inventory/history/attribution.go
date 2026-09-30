package history

import (
	"context"
	"sync"
	"time"
)

// EdgeAttribution — 사람이 지정한 엣지의 앱 한 건.
//
// **스냅샷이 아니다.** 선언은 그 노드를 다시 관측한 결과가 아니므로 노드의 상태 이력에 줄을
// 세우면 안 된다 — 세우면 조회·이력·diff가 저마다 그것을 걸러 내야 하고, 화면이 늘 때마다
// 같은 자리가 다시 샌다. 그래서 타임라인 밖에 따로 둔다.
type EdgeAttribution struct {
	NodeID string
	// Dst — 엣지에 찍힌 상대 주소 그대로. 계약이 `dst_addr`를 `"ip:port"`로 정하므로 포트가
	// 이미 들어 있다 — 따로 두면 같은 정보를 두 곳에 적는 셈이고, 한쪽만 틀리면 매칭이 표시 없이
	// 어긋난다. 상대가 노드로 이어져 주소가 비면 그 노드 ID를 쓴다.
	Dst        string
	AppKey     string
	DeclaredAt time.Time
}

// AttributionStore — 사람이 선언한 앱을 담는 곳. 스냅샷 저장소와 분리돼 있다.
type AttributionStore interface {
	// PutAttribution — 같은 (node,dst,port)에 다시 선언하면 덮어쓴다. 선언은 사람이 고치는
	// 것이므로 append-only가 아니다 — 관측(불변)과 다른 규칙이다.
	PutAttribution(EdgeAttribution) error
	// Attributions — 이 조직의 선언 전부.
	Attributions() ([]EdgeAttribution, error)
}

const attributionSchemaSQL = `
CREATE TABLE IF NOT EXISTS pqcota_edge_attribution (
    org         TEXT NOT NULL,
    node_id     TEXT NOT NULL,
    dst         TEXT NOT NULL,
    app_key     TEXT NOT NULL,
    declared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org, node_id, dst)
);
`

func (p *PgStore) PutAttribution(a EdgeAttribution) error {
	_, err := p.pool.Exec(context.Background(),
		`INSERT INTO pqcota_edge_attribution(org,node_id,dst,app_key)
		 VALUES($1,$2,$3,$4)
		 ON CONFLICT(org,node_id,dst) DO UPDATE SET app_key=$4, declared_at=now()`,
		p.org, a.NodeID, a.Dst, a.AppKey)
	return err
}

func (p *PgStore) Attributions() ([]EdgeAttribution, error) {
	rows, err := p.pool.Query(context.Background(),
		`SELECT node_id,dst,app_key,declared_at FROM pqcota_edge_attribution WHERE org=$1`, p.org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EdgeAttribution
	for rows.Next() {
		var a EdgeAttribution
		if err := rows.Scan(&a.NodeID, &a.Dst, &a.AppKey, &a.DeclaredAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// memAttributions — MemStore의 선언. Pg판과 같은 규칙(덮어쓰기)을 지킨다.
type memAttributions struct {
	mu sync.Mutex
	m  map[[2]string]EdgeAttribution
}

// attrKey — (노드, 상대 주소). 상대 주소가 이미 포트를 담는다.
func attrKey(a EdgeAttribution) [2]string { return [2]string{a.NodeID, a.Dst} }

func (m *MemStore) PutAttribution(a EdgeAttribution) error {
	m.attr.mu.Lock()
	defer m.attr.mu.Unlock()
	if m.attr.m == nil {
		m.attr.m = map[[2]string]EdgeAttribution{}
	}
	if a.DeclaredAt.IsZero() {
		a.DeclaredAt = time.Now().UTC()
	}
	m.attr.m[attrKey(a)] = a
	return nil
}

func (m *MemStore) Attributions() ([]EdgeAttribution, error) {
	m.attr.mu.Lock()
	defer m.attr.mu.Unlock()
	out := make([]EdgeAttribution, 0, len(m.attr.m))
	for _, a := range m.attr.m {
		out = append(out, a)
	}
	return out, nil
}
