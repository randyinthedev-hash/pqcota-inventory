package normalize

import (
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
)

// TK-EVIDENCE-2·3.
//
// 강도를 파생하기 전에 방법부터 정해야 한다. collector는 컴포넌트 프로퍼티
// `pqcota:detection_method`에 방법을 적는데, 한 자산을 두 가지로 본 경우가 있어
// 값이 복합일 수 있다("runtime-introspection+symbol-analysis" — 프로세스에서
// 로드된 것을 보면서 그 바이너리 심볼도 읽었다). 그럴 때 무엇을 택하느냐가
// 강도를 가르므로 여기가 틀리면 EVS 전체가 함께 틀린다.
func TestParseDetectionMethod(t *testing.T) {
	var (
		ri     = commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION
		dt     = commonv1.DetectionMethod_DETECTION_METHOD_DYNAMIC_TRACE
		src    = commonv1.DetectionMethod_DETECTION_METHOD_SOURCE
		art    = commonv1.DetectionMethod_DETECTION_METHOD_ARTIFACT
		sym    = commonv1.DetectionMethod_DETECTION_METHOD_SYMBOL_ANALYSIS
		unspec = commonv1.DetectionMethod_DETECTION_METHOD_UNSPECIFIED
	)
	cases := []struct {
		name     string
		in       string
		envelope commonv1.DetectionMethod
		want     commonv1.DetectionMethod
	}{
		// 어휘 하나하나가 열거값으로 옮겨진다.
		{"runtime-introspection", "runtime-introspection", unspec, ri},
		{"dynamic-trace", "dynamic-trace", unspec, dt},
		{"source", "source", unspec, src},
		{"artifact", "artifact", unspec, art},
		{"symbol-analysis", "symbol-analysis", unspec, sym},

		// 컴포넌트가 적은 것이 Envelope보다 우선한다. Envelope는 수집 전체의 방법이고
		// 프로퍼티는 그 자산 하나를 어떻게 봤나라 더 구체적이다. 더 약해도 그것이 사실이다.
		{"the property beats the Envelope — even when it is weaker", "symbol-analysis", ri, sym},

		// 복합이면 가장 강한 것. 둘 다 사실이므로 약한 쪽으로 깎을 이유가 없다.
		{"combined — the stronger one wins", "runtime-introspection+symbol-analysis", unspec, ri},
		{"combined — independent of the written order", "symbol-analysis+runtime-introspection", unspec, ri},
		{"combined — artifact is stronger than symbol-analysis", "symbol-analysis+artifact", unspec, art},

		// 프로퍼티가 없으면 Envelope로 폴백한다.
		{"no property → Envelope", "", art, art},
		{"Envelope unspecified as well → unspecified", "", unspec, unspec},

		// 아는 어휘가 하나도 없으면 Envelope로 폴백한다. 모르는 문자열을
		// 그럴듯한 값으로 옮기지 않는다(§2.5 추측 금지).
		{"unknown vocabulary → Envelope", "vendor-magic-scan", art, art},
		{"unknown vocabulary with Envelope unspecified → unspecified", "vendor-magic-scan", unspec, unspec},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseDetectionMethod(c.in, c.envelope); got != c.want {
				t.Errorf("parseDetectionMethod(%q, %v) = %v, want %v", c.in, c.envelope, got, c.want)
			}
		})
	}
}

// 어휘는 부분 문자열 매칭으로 찾는다(복합 값을 쪼개지 않고 훑기 위해). 그래서 한 어휘가
// 다른 어휘를 품으면 짧은 쪽이 영영 안 잡히거나 긴 쪽이 잘못 잡힌다 — 어휘를 늘릴 때
// 걸리라고 둔다.
func TestDetectionMethodVocabularyDoesNotOverlap(t *testing.T) {
	vocab := []string{"runtime-introspection", "dynamic-trace", "source", "artifact", "symbol-analysis"}
	for _, a := range vocab {
		for _, b := range vocab {
			if a != b && strings.Contains(a, b) {
				t.Errorf("the term %q contains %q — substring matching cannot tell them apart", a, b)
			}
		}
	}
}
