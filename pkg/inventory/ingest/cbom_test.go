package ingest_test

import (
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/ingest"
)

const validCBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`

// TV-CBOM-1, TD-SIGN-2. CBOM 수신 어댑터.
func TestImportCBOM(t *testing.T) {
	t.Run("valid CBOM with a binding → recorded in the observed lane", func(t *testing.T) {
		disp, env, reason := ingest.ImportCBOM([]byte(validCBOM), "cmdb://node/1", nil)
		if disp != ingest.Accepted {
			t.Fatalf("disp = %v (%s), want Accepted", disp, reason)
		}
		if env.DetectionMethod != commonv1.DetectionMethod_DETECTION_METHOD_ARTIFACT {
			t.Errorf("detection_method = %v, want ARTIFACT (observed lane)", env.DetectionMethod)
		}
		if env.TargetNodeId != "cmdb://node/1" {
			t.Errorf("target_node_id = %q", env.TargetNodeId)
		}
	})

	t.Run("schema mismatch → refused", func(t *testing.T) {
		if disp, _, _ := ingest.ImportCBOM([]byte(`{"bomFormat":"SPDX"}`), "cmdb://node/1", nil); disp != ingest.Rejected {
			t.Errorf("disp = %v, want Rejected", disp)
		}
		if disp, _, _ := ingest.ImportCBOM([]byte(`not json`), "cmdb://node/1", nil); disp != ingest.Rejected {
			t.Errorf("malformed: disp = %v, want Rejected", disp)
		}
	})

	t.Run("no binding → scope decision requested", func(t *testing.T) {
		if disp, _, _ := ingest.ImportCBOM([]byte(validCBOM), "", nil); disp != ingest.NeedsScopeBinding {
			t.Errorf("disp = %v, want NeedsScopeBinding", disp)
		}
	})

	t.Run("signature mismatch (tampered) → refused", func(t *testing.T) {
		reject := func([]byte) bool { return false } // 서명 검증 실패 시뮬레이트
		if disp, _, _ := ingest.ImportCBOM([]byte(validCBOM), "cmdb://node/1", reject); disp != ingest.Rejected {
			t.Errorf("disp = %v, want Rejected (tamper protection)", disp)
		}
	})
}
