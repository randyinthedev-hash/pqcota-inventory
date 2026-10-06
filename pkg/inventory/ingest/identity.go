// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"sort"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// IdentityConflict — 사용자 제공 node_id와 물리 머신 지문이 어긋나는 경우(§1.4 혼선·중복).
type IdentityConflict struct {
	Kind    string   // "duplicate"(한 물리머신을 여러 node_id로) | "collision"(한 node_id를 여러 머신에)
	Key     string   // duplicate=물리머신 키 / collision=node_id
	Members []string // 관련된 node_id들 / 물리머신 키들
}

// CheckIdentity — 회수된 결과들의 (node_id ↔ 물리머신 키) 대응을 교차검증한다.
// 사용자 입력 node_id는 중복/충돌이 가능하므로, 지문(self_assigned_id=지문 결정론 파생)으로 잡는다.
//   - 한 물리머신 키 → 여러 node_id  = **중복**(같은 머신을 여러 이름으로 등록)
//   - 한 node_id → 여러 물리머신 키  = **충돌**(한 이름을 다른 머신에, 재이미지·오라벨)
//
// 지문이 없는 결과는 검증 불가로 건너뛴다(§2.5 정직). 판정은 하지 않는다 — 여기선 surface만.
func CheckIdentity(results []*discoveryv1.CollectionResult) []IdentityConflict {
	keyToNodes := map[string]map[string]bool{}
	nodeToKeys := map[string]map[string]bool{}
	for _, r := range results {
		node := r.GetEnvelope().GetTargetNodeId()
		key := machineKey(r.GetEnvelope().GetMachine())
		if node == "" || key == "" {
			continue
		}
		add(keyToNodes, key, node)
		add(nodeToKeys, node, key)
	}

	var out []IdentityConflict
	for key, nodes := range keyToNodes {
		if len(nodes) > 1 {
			out = append(out, IdentityConflict{Kind: "duplicate", Key: key, Members: keysOf(nodes)})
		}
	}
	for node, keys := range nodeToKeys {
		if len(keys) > 1 {
			out = append(out, IdentityConflict{Kind: "collision", Key: node, Members: keysOf(keys)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind+out[i].Key < out[j].Kind+out[j].Key })
	return out
}

// machineKey — 상관용 대표 물리머신 키. self_assigned_id(지문 결정론 파생)를 우선.
func machineKey(m *commonv1.MachineIdentity) string {
	if m == nil {
		return ""
	}
	if m.GetSelfAssignedId() != "" {
		return m.GetSelfAssignedId()
	}
	for _, v := range []string{m.GetCloudInstanceId(), m.GetMachineId(), m.GetHardwareUuid(), m.GetFqdn()} {
		if v != "" {
			return v
		}
	}
	return ""
}

func add(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
