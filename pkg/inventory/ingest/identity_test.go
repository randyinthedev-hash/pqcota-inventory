// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

func res(nodeID, machineKey string) *discoveryv1.CollectionResult {
	return &discoveryv1.CollectionResult{Envelope: &commonv1.Envelope{
		TargetNodeId: nodeID,
		Machine:      &commonv1.MachineIdentity{SelfAssignedId: machineKey},
	}}
}

// 사용자 node_id 입력의 중복(한 머신 여러 이름)·충돌(한 이름 여러 머신)을 지문으로 잡는다.
func TestCheckIdentity(t *testing.T) {
	results := []*discoveryv1.CollectionResult{
		res("web-01", "node:aaa"),
		res("web-dup", "node:aaa"), // 같은 물리머신(node:aaa)을 다른 이름으로 → 중복
		res("db-01", "node:bbb"),
		res("db-01", "node:ccc"), // 같은 이름을 다른 머신에 → 충돌
		res("clean", "node:ddd"), // 정상
	}
	conflicts := CheckIdentity(results)

	var dup, col bool
	for _, c := range conflicts {
		if c.Kind == "duplicate" && c.Key == "node:aaa" {
			dup = true
			if len(c.Members) != 2 {
				t.Errorf("duplicate member count: %v", c.Members)
			}
		}
		if c.Kind == "collision" && c.Key == "db-01" {
			col = true
		}
	}
	if !dup {
		t.Error("a duplicate (one machine, several node_ids) was not detected")
	}
	if !col {
		t.Error("a conflict (one node_id, several machines) was not detected")
	}
	// 정상 항목은 conflict 아님
	for _, c := range conflicts {
		if c.Key == "node:ddd" || c.Key == "clean" {
			t.Errorf("a healthy entry was reported as a conflict: %+v", c)
		}
	}
}
