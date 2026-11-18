// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
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

func roleEdge(src, dst string, port uint32, role discoveryv1.EdgeRole, group, app string) *discoveryv1.ObservedEdge {
	return &discoveryv1.ObservedEdge{SrcNodeId: src, DstAddr: dst, Port: port, Role: role,
		Protocol: discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS, NegotiatedGroup: group, AppKey: app, AppKeyKind: "exe-path", ObservedCount: 1}
}

// 상세·diff가 역할 화살표로 그린다(S9). 서버 기록은 받은 포트를, 미확인은 그 사실을 붙인다. 같은 앱 키로 관측된 라이브러리를
// 엣지 아래에 붙이되, 그 연결이 그 라이브러리를 썼다는 근거가 아니라고 적는다(S8 화면). 앱 키가 비었거나 다르면 붙이지 않는다.
func TestDetailRoleArrowsAndSameAppAssets(t *testing.T) {
	ssl := &discoveryv1.Finding{Id: "f1", CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL, AppKeys: []string{"/usr/bin/openssl"},
		RuntimeAxes: &discoveryv1.Finding_Openssl{Openssl: &discoveryv1.OpensslAxes{Lib: "libssl.so.3", Version: "3.0.13"}}}
	other := &discoveryv1.Finding{Id: "f2", CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL, AppKeys: []string{"/usr/sbin/other"},
		RuntimeAxes: &discoveryv1.Finding_Openssl{Openssl: &discoveryv1.OpensslAxes{Lib: "libcrypto.so.1.1", Version: "1.1.1w"}}}
	snap := &history.Snapshot{ID: "s", NodeID: "web-02", Findings: []*discoveryv1.Finding{ssl, other}, Edges: []*discoveryv1.ObservedEdge{
		roleEdge("web-02", "10.0.1.10", 443, discoveryv1.EdgeRole_EDGE_ROLE_SERVER, "X25519MLKEM768", "/usr/bin/openssl"),
		roleEdge("web-02", "10.0.1.30:5432", 5432, discoveryv1.EdgeRole_EDGE_ROLE_CLIENT, "secp256r1", ""),
		roleEdge("web-02", "10.0.1.40", 0, discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED, "", "/usr/sbin/sshd"),
	}}
	out := inventory.RenderDetail(snap)
	for _, want := range []string{
		"web-02 ← 10.0.1.10 (on :443)",
		"web-02 → 10.0.1.30:5432",
		"web-02 ↔ 10.0.1.40 (role not confirmed)",
		"same app key in this snapshot: libssl.so.3 3.0.13 (not evidence that this connection used it)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "same app key in this snapshot") != 1 || strings.Contains(out, "libcrypto.so.1.1") && strings.Contains(out, "same app key in this snapshot: libcrypto") {
		t.Errorf("a library was joined to an edge with another or no app key:\n%s", out)
	}
	d := inventory.RenderDiff(&history.Snapshot{ID: "a", NodeID: "web-02"}, snap)
	if !strings.Contains(d, "+ web-02 ← 10.0.1.10 (on :443)") {
		t.Errorf("diff:\n%s", d)
	}
}

// 선언은 클라이언트 기록에만 얹는다(서버·미확인에는 얹지 않는다).
func TestOverlayOnlyOnClientRecords(t *testing.T) {
	store := history.NewMemStore()
	declaredInto(t, store, "node_id,dst,app_key\nweb-02,10.0.1.10,declared.service\n")
	ov := inventory.BuildAttributionOverlay(store)
	for role, want := range map[discoveryv1.EdgeRole]string{
		discoveryv1.EdgeRole_EDGE_ROLE_CLIENT:      "declared.service",
		discoveryv1.EdgeRole_EDGE_ROLE_SERVER:      "",
		discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED: "",
	} {
		if k, _ := ov.Apply(roleEdge("web-02", "10.0.1.10", 443, role, "", "")); k != want {
			t.Errorf("%v: %q, want %q", role, k, want)
		}
	}
}

// 누적 집계가 역할별로 나뉜다(S7·S11). 같은 연결을 양쪽에서 본 기록은 각 쪽에 한 번씩. 옛 이력의 UNSPECIFIED도 「미확인」으로
// 세어 빠지지 않는다. 클라이언트 기록만 있으면 역할 줄이 없다(지금까지의 화면과 같다).
func TestRoleTallyKeepsUnspecified(t *testing.T) {
	store := history.NewMemStore()
	put := func(node string, edges ...*discoveryv1.ObservedEdge) {
		t.Helper()
		if err := store.Append(&history.Snapshot{ID: "s-" + node, NodeID: node, RulesetVersion: "r", Edges: edges}); err != nil {
			t.Fatal(err)
		}
	}
	put("web-01", roleEdge("web-01", "10.0.1.20:443", 443, discoveryv1.EdgeRole_EDGE_ROLE_CLIENT, "X25519MLKEM768", "a"))
	out, err := inventory.RenderStore(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "by role:") {
		t.Errorf("a client-only inventory grew a role line:\n%s", out)
	}
	put("web-02", roleEdge("web-02", "10.0.1.10", 443, discoveryv1.EdgeRole_EDGE_ROLE_SERVER, "X25519MLKEM768", "b"))
	put("old-01", &discoveryv1.ObservedEdge{SrcNodeId: "old-01", DstAddr: "10.0.1.99:22", Port: 22}) // 옛 이력: 역할 없음
	out, err = inventory.RenderStore(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"3 observed edges",
		"by role: client side 1 (🟢 1 · 🔴 0 · ⚪ 0) · server side 1 (🟢 1 · 🔴 0 · ⚪ 0) · role not confirmed 1 (🟢 0 · 🔴 0 · ⚪ 1)",
		"counted once on each side",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}
