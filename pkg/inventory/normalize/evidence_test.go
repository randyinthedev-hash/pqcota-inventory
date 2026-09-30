package normalize_test

import (
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
)

// TK-EVIDENCE-1.
// evidence_strength는 detection_method에서 결정론적으로 파생된다(규정서 §2.3/§2.5).
//
// source·dynamic-trace는 이 리포의 collector가 수집하지 않는다. 소스 스캔은 빌드 검사에
// 맡기고 동적 추적은 침습적이라 하지 않으며, 그런 도구가 낸 CycloneDX를 받아도 ImportCBOM이
// Envelope를 ARTIFACT로 고정한다 — 이 도구가 확인한 것은 그 파일을 읽었다는 사실뿐이라서다.
// 그래도 여섯 값을 전부 못 박는 것은 이 함수가 계약(common.proto)의 열거를 전부 받기
// 때문이다. 생산자가 생겼을 때 강도를 그때 지어내거나 default로 흘러 표시 없이 UNSPECIFIED가
// 되는 일을 막는다. 시험하는 것은 산출 경로가 아니라 함수가 모든 값에 답을 갖는지다.
func TestEvidenceStrength(t *testing.T) {
	cases := []struct {
		name string
		in   commonv1.DetectionMethod
		want commonv1.EvidenceStrength
	}{
		{"runtime-introspection→confirmed",
			commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			commonv1.EvidenceStrength_EVIDENCE_STRENGTH_CONFIRMED},
		{"source→confirmed",
			commonv1.DetectionMethod_DETECTION_METHOD_SOURCE,
			commonv1.EvidenceStrength_EVIDENCE_STRENGTH_CONFIRMED},
		{"dynamic-trace→confirmed",
			commonv1.DetectionMethod_DETECTION_METHOD_DYNAMIC_TRACE,
			commonv1.EvidenceStrength_EVIDENCE_STRENGTH_CONFIRMED},
		{"artifact→inferred-high",
			commonv1.DetectionMethod_DETECTION_METHOD_ARTIFACT,
			commonv1.EvidenceStrength_EVIDENCE_STRENGTH_INFERRED_HIGH},
		{"symbol-analysis→inferred-low",
			commonv1.DetectionMethod_DETECTION_METHOD_SYMBOL_ANALYSIS,
			commonv1.EvidenceStrength_EVIDENCE_STRENGTH_INFERRED_LOW},
		{"unspecified→unspecified (unknown is first-class)",
			commonv1.DetectionMethod_DETECTION_METHOD_UNSPECIFIED,
			commonv1.EvidenceStrength_EVIDENCE_STRENGTH_UNSPECIFIED},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalize.EvidenceStrength(c.in); got != c.want {
				t.Errorf("EvidenceStrength(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
