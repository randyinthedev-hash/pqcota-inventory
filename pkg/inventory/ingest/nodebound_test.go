// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"fmt"
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/declaration"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/ingest"
)

// nodeOpts — 키 파일 모드. pqcota-ingest가 거는 것과 같은 순서다: 노드에 묶인 키로 서명을 보고, 그다음 본문의 노드.
func nodeOpts(store *history.MemStore, keys *sign.NodeKeys) ingest.IngestOptions {
	o := opts(store)
	o.VerifyCollector = func(r *discoveryv1.CollectionResult) error {
		if err := sign.VerifyNodeBound(keys, r); err != nil {
			return err
		}
		return ingest.CheckEdgeSources(r)
	}
	o.Rejections = store
	return o
}

type nodeFixture struct {
	keys                  *sign.NodeKeys
	web01, web02, central string
}

func newNodeFixture(t *testing.T) nodeFixture {
	t.Helper()
	k1, p1, _ := sign.Generate()
	k2, p2, _ := sign.Generate()
	kc, pc, _ := sign.Generate()
	keys, err := sign.ParseNodeKeyFile([]byte(fmt.Sprintf(
		"web-01 openssl-collector,network-collector %s\nweb-02 openssl-collector,network-collector %s\n* attribution-importer,declaration-importer %s\n",
		k1, k2, kc)))
	if err != nil {
		t.Fatal(err)
	}
	return nodeFixture{keys: keys, web01: p1, web02: p2, central: pc}
}

// N1·N2 — web-01의 키는 web-01의 결과만 통과시킨다. 같은 키로 web-02를 적어 다시 서명하면 저장 전에 거부되고,
// 사유가 두 노드를 말한다.
func TestNodeBoundOwnNodeAcceptedOtherNodeRejected(t *testing.T) {
	f := newNodeFixture(t)
	store := history.NewMemStore()
	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{signAs(t, opensslResult("web-01", "libssl.so.3"), "openssl-collector", f.web01)}, nodeOpts(store, f.keys))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accepted != 1 || snapshots(t, store, "web-01") != 1 {
		t.Fatalf("own node: %+v", rep)
	}
	rep, err = ingest.IngestWith([]*discoveryv1.CollectionResult{signAs(t, opensslResult("web-02", "libssl.so.3"), "openssl-collector", f.web01)}, nodeOpts(store, f.keys))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accepted != 0 || rep.Rejected != 1 || snapshots(t, store, "web-02") != 0 {
		t.Fatalf("web-01's key naming web-02 was stored: %+v", rep)
	}
	r := lastRejection(t, store)
	if r.Kind != history.RejectSignature || !strings.Contains(r.Reason, "registered for openssl-collector on web-02") ||
		!strings.Contains(r.Reason, "openssl-collector on web-01") {
		t.Fatalf("rejection: %+v", r)
	}
}

// N12 — 본문의 노드. web-01의 키로 봉투에는 web-01, 엣지의 src_node_id에는 web-02를 넣어 서명한 관측 결과와 앱
// 선언은 거부되고 아무것도 저장되지 않는다. `*` 줄로 통과한 선언도 같다. 상대방(dst_node_id)이 다른 노드인 정상
// 관측은 통과한다.
func TestNodeBoundBodyNodeMustMatch(t *testing.T) {
	f := newNodeFixture(t)

	obs := edgeResult("web-01")
	obs.ObservedEdges[0].SrcNodeId = "web-02"
	signAs(t, obs, "network-collector", f.web01)

	attr := func(src string, priv string) *discoveryv1.CollectionResult {
		rs, err := declaration.ImportAttributionCSV(strings.NewReader("web-01,10.0.0.9:443,billing\n"))
		if err != nil || len(rs) != 1 {
			t.Fatalf("attribution: %v", err)
		}
		rs[0].ObservedEdges[0].SrcNodeId = src
		if err := sign.SignAll(priv, rs); err != nil {
			t.Fatal(err)
		}
		return rs[0]
	}

	store := history.NewMemStore()
	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{obs, attr("web-02", f.central)}, nodeOpts(store, f.keys))
	if err != nil {
		t.Fatal(err)
	}
	as, _ := store.Attributions()
	if rep.Accepted != 0 || rep.Rejected != 2 || len(as) != 0 || snapshots(t, store, "web-01") != 0 || snapshots(t, store, "web-02") != 0 {
		t.Fatalf("a result whose body names another node was stored: report %+v, attributions %+v", rep, as)
	}
	rs, _ := store.Rejections(0)
	for _, r := range rs {
		if !strings.Contains(r.Reason, `edge source node "web-02" is outside the node this result was signed for ("web-01")`) {
			t.Errorf("reason: %+v", r)
		}
	}

	ok := edgeResult("web-01")
	ok.ObservedEdges[0].DstNodeId = "web-02"
	signAs(t, ok, "network-collector", f.web01)
	store = history.NewMemStore()
	rep, err = ingest.IngestWith([]*discoveryv1.CollectionResult{ok, attr("web-01", f.central)}, nodeOpts(store, f.keys))
	if err != nil {
		t.Fatal(err)
	}
	as, _ = store.Attributions()
	if rep.Accepted != 1 || rep.Rejected != 0 || len(as) != 1 || as[0].NodeID != "web-01" {
		t.Fatalf("a peer on another node, or a matching declaration, was refused: %+v %+v", rep, as)
	}
}

// N8 — 노드 식별에는 두 검사(노드에 묶인 서명, 본문의 노드)를 모두 통과한 결과만 들어간다.
func TestNodeBoundRejectedResultMakesNoIdentityConflict(t *testing.T) {
	f := newNodeFixture(t)
	good := opensslResult("web-01", "libssl.so.3")
	good.Envelope.Machine = &commonv1.MachineIdentity{MachineId: "machine-a"}
	signAs(t, good, "openssl-collector", f.web01)
	wrongKey := opensslResult("web-01", "libssl.so.3")
	wrongKey.Envelope.Machine = &commonv1.MachineIdentity{MachineId: "machine-b"}
	signAs(t, wrongKey, "openssl-collector", f.web02)
	wrongBody := edgeResult("web-01")
	wrongBody.Envelope.Machine = &commonv1.MachineIdentity{MachineId: "machine-c"}
	wrongBody.ObservedEdges[0].SrcNodeId = "web-02"
	signAs(t, wrongBody, "network-collector", f.web01)

	store := history.NewMemStore()
	rep, err := ingest.IngestWith([]*discoveryv1.CollectionResult{good, wrongKey, wrongBody}, nodeOpts(store, f.keys))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accepted != 1 || rep.Rejected != 2 || len(rep.Conflicts) != 0 {
		t.Fatalf("report %+v, conflicts %+v", rep, rep.Conflicts)
	}
}
