// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package inventory_test

import (
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// TestUnattributedEdgeIsMarkedNotBlank — 어느 앱인지 못 밝힌 엣지를 빈칸으로 두지 않는다.
//
// 빈칸은 "그런 열이 없다"와 구별되지 않는다. 읽는 사람이 **무엇을 모르는지 알아야** 선언
// 레인으로 채울지 판단한다 — 관측 갭을 고지하는 것과 같은 이유다(§2.6).
func TestUnattributedEdgeIsMarkedNotBlank(t *testing.T) {
	snap := &history.Snapshot{
		ID: "s1", NodeID: "web-01", RulesetVersion: "r1",
		Completeness: &commonv1.Completeness{Note: "1 of 3 edges could not be attributed to an app"},
		Edges: []*discoveryv1.ObservedEdge{
			{SrcNodeId: "web-01", DstAddr: "10.0.0.5:443", Port: 443, AppKey: "payment.service", AppKeyKind: "systemd-unit"},
			{SrcNodeId: "web-01", DstAddr: "10.0.0.6:443", Port: 443, AppKey: "/opt/app/bin/svc", AppKeyKind: "exe-path"},
			{SrcNodeId: "web-01", DstAddr: "10.0.0.7:443", Port: 443}, // 못 잡음
		},
	}
	out := inventory.RenderDetail(snap)

	if !strings.Contains(out, "@payment.service") {
		t.Error("the systemd unit was not emitted")
	}
	// 근거가 유닛이 아니면 그 사실을 함께 적는다 — 같은 값이라도 얼마나 믿을지가 다르다.
	if !strings.Contains(out, "@/opt/app/bin/svc(exe-path)") {
		t.Error("it is an exe path but the basis was not stated")
	}
	if !strings.Contains(out, "@?") {
		t.Error("an edge with no app named is left blank — indistinguishable from the column not being there")
	}
	// 왜 못 잡았는지는 완전성 노트에 적힌다. 화면이 그것을 감추면 안 된다.
	if !strings.Contains(out, "could not be attributed to an app") {
		t.Error("the completeness note does not appear on screen")
	}
}
