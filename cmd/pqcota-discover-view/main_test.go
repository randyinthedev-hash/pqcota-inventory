// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// 토폴로지의 화살표는 개시자 → 수신자다. 서버 기록(관측 노드가 받음)은 상대(클라이언트)에서 관측 노드로, 역할 미확인은
// 방향 없이 점선으로 그린다. 같은 상대라도 역할이 다르면 선이 따로다.
func TestObservedDOTDirectionFollowsRole(t *testing.T) {
	ip2node := map[string]string{"10.0.1.10": "web-01", "10.0.1.20": "web-02"}
	e := func(src, dst string, port uint32, role discoveryv1.EdgeRole) *discoveryv1.ObservedEdge {
		return &discoveryv1.ObservedEdge{SrcNodeId: src, DstAddr: dst, Port: port, Role: role,
			Protocol: discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS, NegotiatedGroup: "X25519MLKEM768"}
	}
	dot := renderObservedDOT([]*discoveryv1.ObservedEdge{
		e("web-01", "10.0.1.20:443", 443, discoveryv1.EdgeRole_EDGE_ROLE_CLIENT),
		e("web-02", "10.0.1.10", 443, discoveryv1.EdgeRole_EDGE_ROLE_SERVER),
		e("web-02", "10.0.1.10", 0, discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED),
	}, ip2node)
	if strings.Count(dot, `"web-01" -> "web-02"`) != 2 {
		t.Errorf("the client and server records of one connection should both point web-01 → web-02:\n%s", dot)
	}
	if !strings.Contains(dot, `"web-02" -> "web-01" [`) || strings.Count(dot, "dir=none, style=dashed") != 1 {
		t.Errorf("the unconfirmed record is not drawn undirected from its observing node:\n%s", dot)
	}
}
