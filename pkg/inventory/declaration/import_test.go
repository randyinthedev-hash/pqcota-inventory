// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package declaration_test

import (
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/declaration"
)

// TC-S8. 선언 임포트 → 선언 레인.
func TestImportCSV(t *testing.T) {
	csv := "node_id,crypto_runtime,component\ncmdb://n1,openssl,libssl\ncmdb://n2,jca,jca-provider-chain\n"
	results, err := declaration.ImportCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (header excluded)", len(results))
	}
	r := results[0]
	// 선언은 관측 아님 → detection_method UNSPECIFIED (evidence_strength unknown, 정직).
	if r.GetEnvelope().GetDetectionMethod() != commonv1.DetectionMethod_DETECTION_METHOD_UNSPECIFIED {
		t.Errorf("detection_method = %v, want UNSPECIFIED (declared is not observed)", r.GetEnvelope().GetDetectionMethod())
	}
	if r.GetEnvelope().GetCollectorId() != "declaration-importer" {
		t.Errorf("collector_id = %q", r.GetEnvelope().GetCollectorId())
	}
	if !strings.Contains(string(r.GetCbomCyclonedx()), `"declared"`) {
		t.Errorf("no lane=declared label: %s", r.GetCbomCyclonedx())
	}
}
