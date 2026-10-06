// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

// Package ingest — CBOM 수신 어댑터(위임 수신 설계 「어댑터 명세」, SV-2·SD-7).
// CBOMkit 등이 산출한 표준 CycloneDX를 "수신·처리"만 한다 — CBOMkit을 실행하지 않는다(§1.1).
package ingest

import (
	"encoding/json"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
)

// ValidateResult — `ValidateCBOM`의 구조 검증 결과. `ImportCBOM`이 적재 전 내부에서 사용한다.
type ValidateResult struct {
	OK          bool
	Reason      string
	SpecVersion string
}

// ValidateCBOM — 제출된 CycloneDX의 최소 구조 적합성을 검증한다(TV-CBOM-1, §5 핸드오프).
// bomFormat·specVersion을 확인해 부적합 CBOM 등재를 거부한다. 완전 JSON-schema 검증은 후속.
func ValidateCBOM(raw []byte) ValidateResult {
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ValidateResult{OK: false, Reason: "malformed JSON"}
	}
	if doc.BomFormat != "CycloneDX" {
		return ValidateResult{OK: false, Reason: "not a CycloneDX document"}
	}
	if doc.SpecVersion != "1.6" && doc.SpecVersion != "1.7" {
		return ValidateResult{OK: false, Reason: "unsupported specVersion", SpecVersion: doc.SpecVersion}
	}
	return ValidateResult{OK: true, SpecVersion: doc.SpecVersion}
}

// Disposition — 수신 결과.
type Disposition int

const (
	Accepted          Disposition = iota // 관측 레인으로 등재
	Rejected                             // 검증/서명 실패 → 거부
	NeedsScopeBinding                    // target_node_id 없음 → 스코프 판정(SD-5)으로
)

// ImportCBOM — 미리 생성된 CycloneDX를 수신해 관측 레인 Envelope를 부착한다(SV-2·SD-7).
//
// 순서: (1) 서명 검증(verifySig, nil이면 생략) → 실패 시 거부(TD-SIGN-2 변조 방지),
// (2) 구조 검증 → 실패 시 거부, (3) 스코프 바인딩 확인 → 없으면 판정 요청,
// (4) detection_method=ARTIFACT(source/artifact 관측 레인) Envelope 부착 → 등재(TV-CBOM-1).
//
// evidence_strength는 코어 강화 단계가 detection_method에서 파생한다(Envelope엔 넣지 않음, §1.2).
func ImportCBOM(raw []byte, targetNodeID string, verifySig func([]byte) bool) (Disposition, *commonv1.Envelope, string) {
	if verifySig != nil && !verifySig(raw) {
		return Rejected, nil, "signature mismatch"
	}
	if v := ValidateCBOM(raw); !v.OK {
		return Rejected, nil, v.Reason
	}
	if targetNodeID == "" {
		return NeedsScopeBinding, nil, "no target_node_id binding"
	}
	env := &commonv1.Envelope{
		DetectionMethod: commonv1.DetectionMethod_DETECTION_METHOD_ARTIFACT,
		TargetNodeId:    targetNodeID,
	}
	return Accepted, env, ""
}
