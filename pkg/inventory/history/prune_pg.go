// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"time"
)

// Prune — 영속 저장소의 보존 정책 집행. apply=false면 **아무것도 지우지 않고** 계획만 낸다.
// 판정 규칙은 MemStore와 같다(prunable) — 최신 불가침, 두 축은 보수적으로(둘 다 버려도 된다고
// 할 때만) 판정한다.
func (p *PgStore) Prune(pol Policy, apply bool) (*PruneReport, error) {
	if err := pol.validate(); err != nil {
		return nil, err
	}
	ctx := context.Background()
	now := time.Now().UTC()
	rep := &PruneReport{Applied: apply, Policy: pol}

	nodes, err := p.Nodes()
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		np, err := p.pruneNode(ctx, node, pol, now, apply)
		if err != nil {
			return nil, err
		}
		if np != nil {
			rep.Nodes = append(rep.Nodes, *np)
		}
	}
	return rep, nil
}

// pruneNode — 한 노드의 절단. 적재([PgStore.Append])와 같은 노드 잠금 안에서 스냅샷 목록과 현재 스냅샷을
// 다시 읽고 판정한다. 그래야 적재가 옛 스냅샷을 현재로 다시 쓰는 것과 겹쳐도 현재 스냅샷 참조가
// 끊기지 않는다. apply=false면 같은 판정을 하고 롤백한다.
func (p *PgStore) pruneNode(ctx context.Context, node string, pol Policy, now time.Time, apply bool) (*NodePrune, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // 커밋한 뒤의 롤백은 아무 일도 하지 않는다
	if err := p.lockNode(ctx, tx, node); err != nil {
		return nil, err
	}
	snaps, err := p.snapshots(ctx, tx, node) // seq 오름차순
	if err != nil {
		return nil, err
	}
	cur := ""
	if seq, ok, err := p.currentSeq(ctx, tx, node); err != nil {
		return nil, err
	} else if ok {
		for _, s := range snaps {
			if s.Seq == seq {
				cur = s.ID
			}
		}
	}
	victims := prunable(snaps, pol, now, cur)
	if len(victims) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(victims))
	for _, v := range victims {
		ids = append(ids, v.ID)
	}
	np := &NodePrune{NodeID: node, Snapshots: len(victims), UpTo: victims[len(victims)-1].CreatedAt}
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM pqcota_observations WHERE org=$1 AND node_id=$2 AND snapshot_id = ANY($3)`,
		p.org, node, ids).Scan(&np.Observations); err != nil {
		return nil, err
	}
	if !apply {
		return np, nil
	}
	// 관측 기록 → 스냅샷 순으로 지운다(고아 관측 기록이 남지 않게).
	if _, err := tx.Exec(ctx,
		`DELETE FROM pqcota_observations WHERE org=$1 AND node_id=$2 AND snapshot_id = ANY($3)`, p.org, node, ids); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM pqcota_snapshots WHERE org=$1 AND node_id=$2 AND id = ANY($3)`, p.org, node, ids); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO pqcota_retention_events(org,node_id,pruned_upto,snapshots,observations,policy)
		 VALUES($1,$2,$3,$4,$5,$6)`,
		p.org, node, np.UpTo, np.Snapshots, np.Observations, pol.String()); err != nil {
		return nil, err
	}
	return np, tx.Commit(ctx)
}

// RetentionEvents — 그 노드에 일어난 절단 기록(오래된 것부터).
func (p *PgStore) RetentionEvents(nodeID string) ([]RetentionEvent, error) {
	rows, err := p.pool.Query(context.Background(),
		`SELECT node_id, pruned_upto, snapshots, observations, policy, executed_at
		 FROM pqcota_retention_events WHERE org=$1 AND node_id=$2 ORDER BY seq ASC`, p.org, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RetentionEvent
	for rows.Next() {
		var e RetentionEvent
		if err := rows.Scan(&e.NodeID, &e.PrunedUpTo, &e.Snapshots, &e.Observations, &e.Policy, &e.ExecutedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
