package history_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// PQCOTA_TEST_DSN이 있을 때만 실행(로컬/CI Postgres). 기본 `go test`는 스킵.
func TestPgStore(t *testing.T) {
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	ctx := context.Background()
	st, err := history.NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// 실행마다 유니크 노드(append-only라 삭제 안 함).
	node := "host://pgtest-" + strconv.FormatInt(time.Now().UnixNano(), 36)

	f := &discoveryv1.Finding{
		Id:               "f1",
		CryptoRuntime:    commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL,
		EvidenceStrength: commonv1.EvidenceStrength_EVIDENCE_STRENGTH_CONFIRMED,
		RuntimeAxes:      &discoveryv1.Finding_Openssl{Openssl: &discoveryv1.OpensslAxes{Lib: "libcrypto.so.3", Version: "3.5.4"}},
	}
	comp := &commonv1.Completeness{LayersMissing: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_ARTIFACT}}

	// 통신 엣지 관측 레인(인벤토리 설계 §6) — 라운드트립 보존 검증.
	edge := &discoveryv1.ObservedEdge{
		SrcNodeId: node, DstNodeId: "db-01", Port: 5432,
		Protocol: discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS, NegotiatedGroup: "X25519MLKEM768",
		DetectionMethod: commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
	}

	if err := st.Append(&history.Snapshot{ID: "s1", NodeID: node, RulesetVersion: "r1", Findings: []*discoveryv1.Finding{f}, Completeness: comp, Edges: []*discoveryv1.ObservedEdge{edge}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(&history.Snapshot{ID: "s2", NodeID: node, RulesetVersion: "r1", Findings: []*discoveryv1.Finding{f}}); err != nil {
		t.Fatal(err)
	}

	// Latest = 마지막 append.
	latest, err := st.Latest(node)
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.ID != "s2" {
		t.Fatalf("latest = %v, want s2", latest)
	}

	// 라운드트립: Finding·Envelope 필드 보존.
	all, err := st.Snapshots(node)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("snapshots = %d, want 2 (append-only)", len(all))
	}
	got := all[0].Findings[0]
	if got.GetId() != "f1" || got.GetOpenssl().GetVersion() != "3.5.4" {
		t.Errorf("Finding was not preserved (protojson round-trip): %+v", got)
	}
	if len(all[0].Completeness.GetLayersMissing()) != 1 {
		t.Errorf("the completeness map was not preserved: %+v", all[0].Completeness)
	}
	// 엣지 레인 라운드트립.
	if len(all[0].Edges) != 1 || all[0].Edges[0].GetNegotiatedGroup() != "X25519MLKEM768" {
		t.Errorf("the observed edges were not preserved: %+v", all[0].Edges)
	}
	if len(all[1].Edges) != 0 {
		t.Errorf("a snapshot with no edges must have empty edges: %+v", all[1].Edges)
	}

	// 미등록 노드 → nil.
	if n, _ := st.Latest("host://none-" + node); n != nil {
		t.Error("an unregistered node must be nil")
	}
}
