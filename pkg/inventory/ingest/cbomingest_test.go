package ingest_test

import (
	"testing"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/ingest"
)

const sampleCBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
  {"type":"cryptographic-asset","name":"libcrypto.so.3","properties":[
    {"name":"pqcota:crypto_runtime","value":"openssl"},
    {"name":"pqcota:openssl.fork","value":"OpenSSL"}]}]}`

// 외부 CBOM 수신 → 검증 통과분만 정규화·적재(SV-2). 부적합은 저장 안 함.
func TestIngestCBOM(t *testing.T) {
	store := history.NewMemStore()
	disp, err := ingest.IngestCBOM([]byte(sampleCBOM), "cbom-node", nil, "snap", "r", store)
	if err != nil || disp != ingest.Accepted {
		t.Fatalf("disp=%v err=%v (want Accepted)", disp, err)
	}
	snap, _ := store.Latest("cbom-node")
	if snap == nil || len(snap.Findings) != 1 {
		t.Fatalf("the ingested CBOM snapshot produced no finding: %+v", snap)
	}

	// 구조 부적합 → 거부, 저장 안 함.
	store2 := history.NewMemStore()
	if d, _ := ingest.IngestCBOM([]byte(`{"bomFormat":"SPDX"}`), "n", nil, "s", "r", store2); d != ingest.Rejected {
		t.Errorf("a non-CycloneDX input must be Rejected, got %v", d)
	}
	if s, _ := store2.Latest("n"); s != nil {
		t.Error("a refused CBOM was stored")
	}

	// 스코프 앵커(target) 없으면 등재요청 — 저장 안 함.
	if d, _ := ingest.IngestCBOM([]byte(sampleCBOM), "", nil, "s", "r", history.NewMemStore()); d != ingest.NeedsScopeBinding {
		t.Errorf("with no anchor it must be NeedsScopeBinding, got %v", d)
	}
}
