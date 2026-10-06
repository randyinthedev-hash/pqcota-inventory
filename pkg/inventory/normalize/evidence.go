// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package normalize — 정규화 파이프라인(규정서 §2.4).
// 강화·검증·동일성해소가 코어 단독 책임 — Collector는 강화하지 않는다(디스커버리 설계 §3, contracts/README).
package normalize

import commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"

// EvidenceStrength derives the evidence strength from a detection method.
//
// 규정서 §2.3 표를 결정론적 함수로 고정한 것으로, evidence_strength의 유일 소스다
// (디스커버리 설계 §3, 파이프라인 ③강화 단계). Collector 출력에는 존재하지 않으며,
// 원본(detection_method)에서 항상 재계산 가능해야 한다(규정서 §1.2).
//
// 미지정/미지 method는 UNSPECIFIED(=unknown)를 반환한다 — "unknown도 1급 증거"(§2.5).
func EvidenceStrength(m commonv1.DetectionMethod) commonv1.EvidenceStrength {
	switch m {
	case commonv1.DetectionMethod_DETECTION_METHOD_SOURCE,
		commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
		commonv1.DetectionMethod_DETECTION_METHOD_DYNAMIC_TRACE:
		return commonv1.EvidenceStrength_EVIDENCE_STRENGTH_CONFIRMED
	case commonv1.DetectionMethod_DETECTION_METHOD_ARTIFACT:
		return commonv1.EvidenceStrength_EVIDENCE_STRENGTH_INFERRED_HIGH
	case commonv1.DetectionMethod_DETECTION_METHOD_SYMBOL_ANALYSIS:
		return commonv1.EvidenceStrength_EVIDENCE_STRENGTH_INFERRED_LOW
	default:
		return commonv1.EvidenceStrength_EVIDENCE_STRENGTH_UNSPECIFIED
	}
}
