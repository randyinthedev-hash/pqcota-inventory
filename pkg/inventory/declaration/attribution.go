// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package declaration

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// KindDeclared — 이 app_key가 무엇에 기대고 있나. `systemd-unit`·`exe-path` 옆에 오는 세 번째 값이다.
//
// 계약을 늘리지 않고 이 자리를 쓰는 이유: `ObservedEdge.detection_method`는 **엣지 자체를 어떻게
// 관측했나**를 말하지 키의 출처가 아니다. 거기에 UNSPECIFIED를 넣으면 "이 통신을 실제로 봤다"는
// 사실까지 흐려진다. 엣지는 관측된 것이 맞고, **어느 앱이 열었는지만** 사람이 적은 것이다.
const KindDeclared = "declared"

// EdgeAttribution — 사람이 지정한 엣지의 앱 한 건.
type EdgeAttribution struct {
	NodeID string // 관측 호스트(엣지의 src)
	// Dst — 엣지에 찍힌 상대 주소 그대로. 계약이 `dst_addr`를 `"ip:port"`로 정하므로 포트가
	// 이미 들어 있다 — 따로 받으면 같은 정보를 두 번 적게 되고, 한쪽만 틀리면 표시 없이 안 맞는다.
	Dst    string
	AppKey string
}

// ImportAttributionCSV — 선언 CSV(node_id,dst,app_key)를 선언 레인 CollectionResult로 임포트.
//
// **관측 결과를 고치지 않는다.** 이것은 자기 레인으로 따로 쌓이고(detection_method=UNSPECIFIED),
// 관측 엣지와 합치는 일은 화면에서 한다 — 적재가 관측을 고치면 collector의 서명과 어긋나고,
// raw_capture에서 다시 계산할 때 저장된 값과 달라진다(검토 중인 설계 §7.5).
func ImportAttributionCSV(r io.Reader) ([]*discoveryv1.CollectionResult, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	byNode := map[string][]EdgeAttribution{}
	var order []string
	for i, row := range rows {
		if len(row) < 3 {
			continue
		}
		if i == 0 && strings.EqualFold(strings.TrimSpace(row[0]), "node_id") {
			continue // 헤더
		}
		a := EdgeAttribution{
			NodeID: strings.TrimSpace(row[0]),
			Dst:    strings.TrimSpace(row[1]),
			AppKey: strings.TrimSpace(row[2]),
		}
		// 셋 중 하나라도 비면 어느 엣지를 가리키는지 알 수 없다. 추측하지 않고 알린다 —
		// 앱을 잘못 짚으면 조치 대상이 바뀐다.
		if a.NodeID == "" || a.Dst == "" || a.AppKey == "" {
			return nil, fmt.Errorf("row %d: node_id, dst and app_key are all required", i+1)
		}
		if _, ok := byNode[a.NodeID]; !ok {
			order = append(order, a.NodeID)
		}
		byNode[a.NodeID] = append(byNode[a.NodeID], a)
	}
	out := make([]*discoveryv1.CollectionResult, 0, len(order))
	for _, node := range order {
		out = append(out, buildDeclaredAttribution(node, byNode[node]))
	}
	return out, nil
}

func buildDeclaredAttribution(node string, as []EdgeAttribution) *discoveryv1.CollectionResult {
	edges := make([]*discoveryv1.ObservedEdge, 0, len(as))
	var raw strings.Builder
	for _, a := range as {
		edges = append(edges, &discoveryv1.ObservedEdge{
			SrcNodeId: a.NodeID,
			DstAddr:   a.Dst,
			AppKey:    a.AppKey,
			// 이 엣지는 관측된 것이 아니다 — 앱 이름을 나르는 그릇일 뿐이다.
			DetectionMethod: commonv1.DetectionMethod_DETECTION_METHOD_UNSPECIFIED,
			AppKeyKind:      KindDeclared,
		})
		fmt.Fprintf(&raw, "%s,%s,%s\n", a.NodeID, a.Dst, a.AppKey)
	}
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      "attribution-importer",
			CollectorVersion: "0.1.0",
			DetectionMethod:  commonv1.DetectionMethod_DETECTION_METHOD_UNSPECIFIED, // 선언은 관측 아님
			TargetNodeId:     node,
			CollectorLicense: "Apache-2.0",
		},
		// 선언 원본 — 매핑 규칙이 바뀌면 여기서 다시 만든다(§2.4 step 1).
		RawCapture:    []byte(raw.String()),
		RawFormat:     "attribution/csv-v1",
		ObservedEdges: edges,
		// 관측한 계층이 없다 — 이 결과는 아무것도 관측하지 않았다.
		Completeness: &commonv1.Completeness{
			Note: "an app declared by a person — not an observation. Used only to fill an empty app_key on an observed edge, at view time",
		},
	}
}
