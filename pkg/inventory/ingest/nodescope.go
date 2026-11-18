// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"fmt"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// CheckEdgeSources — 본문의 엣지가 서명한 노드에서 나간 것인가. 엣지의 src_node_id가 봉투의 target_node_id와
// 다르면 오류다.
//
// 서명은 봉투의 노드로 확인하지만, 저장할 때 본문의 노드를 쓰는 곳이 있다. 앱 선언은 엣지의 src_node_id로
// 선언 기록에 들어가고(attributionsOf), 관측 엣지의 src_node_id는 화면과 엣지 동일성이 「출발 노드」로 쓴다.
// 키를 노드 A에 묶어도 봉투에 A, 본문에 B를 넣어 서명하면 B의 기록이 바뀐다. 그래서 노드에 묶은 키로 검증할
// 때는 이것도 본다. 엣지의 상대방(dst_node_id·dst_addr)은 관측한 쪽이 본 것을 적는 자리라 보지 않는다.
//
// 지금의 수집기(netcap의 출발 노드는 캡처 호스트, 곧 노드 인자)와 선언 도구(노드마다 결과를 나누고 src_node_id를
// 그 노드로 둔다)는 이미 이 규칙을 지킨다.
//
// GATE: 배선 필수 — pqcota-ingest의 PQCOTA_VERIFY_KEY_FILE.
func CheckEdgeSources(r *discoveryv1.CollectionResult) error {
	node := r.GetEnvelope().GetTargetNodeId()
	for _, e := range r.GetObservedEdges() {
		if src := e.GetSrcNodeId(); src != node {
			return fmt.Errorf("edge source node %q is outside the node this result was signed for (%q)", src, node)
		}
	}
	return nil
}
