// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package inventory_test

import (
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// RenderStore — 적재된 히스토리 저장소 전체를 읽어 누적 인벤토리 뷰 + 등급 집계.
func TestRenderStore(t *testing.T) {
	store := history.NewMemStore()
	_ = store.Append(&history.Snapshot{ID: "s1", NodeID: "web-01", RulesetVersion: "r",
		Findings: []*discoveryv1.Finding{{CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL}},
		Edges: []*discoveryv1.ObservedEdge{{
			SrcNodeId: "web-01", DstNodeId: "app-01",
			Protocol:        discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS,
			NegotiatedGroup: "X25519MLKEM768", // 🟢
		}},
	})
	_ = store.Append(&history.Snapshot{ID: "s2", NodeID: "db-01", RulesetVersion: "r",
		Edges: []*discoveryv1.ObservedEdge{{
			SrcNodeId: "web-01", DstNodeId: "db-01",
			Protocol:        discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS,
			NegotiatedGroup: "x25519", // 🔴
		}},
	})

	// 머신 메타데이터: 엔드포인트 + 프로필 → 노드 헤더에 사람-대면 정보.
	meta := inventory.NewMemMetaStore()
	_ = meta.UpsertEndpoint(&inventoryv1.MachineEndpoint{NodeId: "web-01", Name: "Web 1", Ip: "10.0.0.2", Port: 22})
	_ = meta.UpsertProfile(&inventoryv1.MachineProfile{NodeId: "web-01", DisplayName: "Payment Web",
		Environment: inventoryv1.Environment_ENVIRONMENT_PRODUCTION, Role: "web", Owner: "pay-team"})

	out, err := inventory.RenderStore(store, meta)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"web-01", "db-01", "1 assets", "2 observed edges", "🟢 PQC 1", "🔴 classical 1",
		"Web 1", "10.0.0.2:22", "Payment Web", "production", "owner=pay-team"} {
		if !strings.Contains(out, want) {
			t.Errorf("the RenderStore output does not contain %q:\n%s", want, out)
		}
	}

	// nil MetaStore도 안전(헤더만 생략).
	if _, err := inventory.RenderStore(store, nil); err != nil {
		t.Fatalf("nil meta: %v", err)
	}
}
