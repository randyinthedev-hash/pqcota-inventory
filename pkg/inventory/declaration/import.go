// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package declaration — 선언 임포터(인벤토리 설계 「선언 임포터」, SV-1).
// 사용자의 기존 선언 인벤토리(CMDB/CSV)를 선언 레인으로 임포트한다. CBOM 아님(§3.3 선언≠관측).
package declaration

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strings"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// ImportCSV — 선언 CSV(node_id,crypto_runtime,component)를 선언 레인 CollectionResult로 임포트.
// 관측이 아니라 선언이므로 detection_method는 UNSPECIFIED(→ evidence_strength unknown, 정직).
// lane=declared로 라벨해 Inventory 대조(Phase 1)에서 관측과 구분한다(§3.3).
func ImportCSV(r io.Reader) ([]*discoveryv1.CollectionResult, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []*discoveryv1.CollectionResult
	for i, row := range rows {
		if len(row) < 3 {
			continue
		}
		if i == 0 && strings.EqualFold(strings.TrimSpace(row[0]), "node_id") {
			continue // 헤더
		}
		node := strings.TrimSpace(row[0])
		runtime := strings.TrimSpace(row[1])
		comp := strings.TrimSpace(row[2])
		out = append(out, buildDeclared(node, runtime, comp))
	}
	return out, nil
}

func buildDeclared(node, runtime, component string) *discoveryv1.CollectionResult {
	cbom, _ := json.Marshal(map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"components": []map[string]any{{
			"type": "cryptographic-asset",
			"name": component,
			"properties": []map[string]string{
				{"name": "pqcota:crypto_runtime", "value": runtime},
				{"name": "pqcota:lane", "value": "declared"},
			},
		}},
	})
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      "declaration-importer",
			CollectorVersion: "0.1.0",
			DetectionMethod:  commonv1.DetectionMethod_DETECTION_METHOD_UNSPECIFIED, // 선언은 관측 아님
			TargetNodeId:     node,
			CollectorLicense: "Apache-2.0",
		},
		// 선언 원본 한 행 — 매핑 규칙이 바뀌면 여기서 다시 만든다(§2.4 step 1).
		RawCapture:           []byte(node + "," + runtime + "," + component),
		RawFormat:            "declaration/csv-v1",
		CbomCyclonedx:        cbom,
		CyclonedxSpecVersion: "1.6",
	}
}
